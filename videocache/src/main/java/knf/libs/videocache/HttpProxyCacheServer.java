package knf.libs.videocache;

import android.content.Context;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.text.format.Formatter;

import knf.libs.videocache.file.DiskUsage;
import knf.libs.videocache.file.FileNameGenerator;
import knf.libs.videocache.file.Md5FileNameGenerator;
import knf.libs.videocache.file.TotalCountLruDiskUsage;
import knf.libs.videocache.file.TotalSizeLruDiskUsage;
import knf.libs.videocache.headers.EmptyHeadersInjector;
import knf.libs.videocache.headers.HeaderInjector;
import knf.libs.videocache.sourcestorage.SourceInfoStorage;
import knf.libs.videocache.sourcestorage.SourceInfoStorageFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static knf.libs.videocache.Preconditions.checkAllNotNull;
import static knf.libs.videocache.Preconditions.checkNotNull;

/**
 * Simple lightweight proxy server with file caching support that handles HTTP requests.
 * Typical usage:
 * <pre><code>
 * public onCreate(Bundle state) {
 *      super.onCreate(state);
 *
 *      HttpProxyCacheServer proxy = getProxy();
 *      String proxyUrl = proxy.getProxyUrl(VIDEO_URL);
 *      videoView.setVideoPath(proxyUrl);
 * }
 *
 * private HttpProxyCacheServer getProxy() {
 * // should return single instance of HttpProxyCacheServer shared for whole app.
 * }
 * </code></pre>
 *
 * @author Alexey Danilov (danikula@gmail.com).
 */
public class HttpProxyCacheServer {

    private static final Logger LOG = LoggerFactory.getLogger("HttpProxyCacheServer");
    private static String PROXY_HOST = "127.0.0.1";

    private final Object clientsLock = new Object();
    private final ExecutorService socketProcessor = Executors.newFixedThreadPool(8);
    private final Map<String, HttpProxyCacheServerClients> clientsMap = new ConcurrentHashMap<>();
    private final ServerSocket serverSocket;
    private final int port;
    private final Thread waitConnectionThread;
    private final Config config;
    private final Pinger pinger;

    public HttpProxyCacheServer(Context context) {
        this(new Builder(context).buildConfig(),null);
    }

    public HttpProxyCacheServer(Context context, String customHost) {
        this(new Builder(context).buildConfig(),customHost == null ? getIP(context) : customHost);
    }

    private static String getIP(Context context){
        return Formatter.formatIpAddress(((WifiManager)context.getApplicationContext().getSystemService(Context.WIFI_SERVICE)).getConnectionInfo().getIpAddress());
    }

    private HttpProxyCacheServer(Config config,String host) {
        PROXY_HOST = host;
        this.config = checkNotNull(config);
        try {
            InetAddress inetAddress = InetAddress.getByName(PROXY_HOST);
            this.serverSocket = new ServerSocket(0, 8, inetAddress);
            this.port = serverSocket.getLocalPort();
            IgnoreHostProxySelector.install(PROXY_HOST, port);
            CountDownLatch startSignal = new CountDownLatch(1);
            this.waitConnectionThread = new Thread(new WaitRequestsRunnable(startSignal));
            this.waitConnectionThread.start();
            startSignal.await(); // freeze thread, wait for server starts
            this.pinger = new Pinger(PROXY_HOST, port);
            LOG.info("Proxy cache server started. Is it alive? " + isAlive());
        } catch (IOException | InterruptedException e) {
            socketProcessor.shutdown();
            throw new IllegalStateException("Error starting local proxy server", e);
        }
    }

    public String getProxyUrl(String url) {
        return getProxyUrl(url, true);
    }

    public String getProxyUrl(String url, boolean allowCachedFileUri) {
        if (allowCachedFileUri && isCached(url)) {
            File cacheFile = getCacheFile(url);
            touchFileSafely(cacheFile);
            return Uri.fromFile(cacheFile).toString();
        }
        return isAlive() ? appendToProxyUrl(url) : url;
    }

    public void registerCacheListener(CacheListener cacheListener, String url) {
        checkAllNotNull(cacheListener, url);
        synchronized (clientsLock) {
            try {
                getClients(url).registerCacheListener(cacheListener);
            } catch (ProxyCacheException e) {
                LOG.warn("Error registering cache listener", e);
            }
        }
    }

    public void unregisterCacheListener(CacheListener cacheListener, String url) {
        checkAllNotNull(cacheListener, url);
        synchronized (clientsLock) {
            try {
                getClients(url).unregisterCacheListener(cacheListener);
            } catch (ProxyCacheException e) {
                LOG.warn("Error registering cache listener", e);
            }
        }
    }

    public void unregisterCacheListener(CacheListener cacheListener) {
        checkNotNull(cacheListener);
        synchronized (clientsLock) {
            for (HttpProxyCacheServerClients clients : clientsMap.values()) {
                clients.unregisterCacheListener(cacheListener);
            }
        }
    }

    /**
     * Checks is cache contains fully cached file for particular url.
     *
     * @param url an url cache file will be checked for.
     * @return {@code true} if cache contains fully cached file for passed in parameters url.
     */
    public boolean isCached(String url) {
        checkNotNull(url, "Url can't be null!");
        return getCacheFile(url).exists();
    }

    public void shutdown() {
        LOG.info("Shutdown proxy server");

        shutdownClients();

        config.sourceInfoStorage.release();

        waitConnectionThread.interrupt();
        try {
            if (!serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            onError(new ProxyCacheException("Error shutting down proxy server", e));
        }
    }

    private boolean isAlive() {
        return pinger.ping(3, 70);   // 70+140+280=max~500ms
    }

    private String appendToProxyUrl(String url) {
        return String.format(Locale.US, "http://%s:%d/%s", PROXY_HOST, port, ProxyCacheUtils.encode(url));
    }

    private File getCacheFile(String url) {
        File cacheDir = config.cacheRoot;
        String fileName = config.fileNameGenerator.generate(url);
        return new File(cacheDir, fileName);
    }

    private void touchFileSafely(File cacheFile) {
        try {
            config.diskUsage.touch(cacheFile);
        } catch (IOException e) {
            LOG.error("Error touching file " + cacheFile, e);
        }
    }

    private void shutdownClients() {
        synchronized (clientsLock) {
            for (HttpProxyCacheServerClients clients : clientsMap.values()) {
                clients.shutdown();
            }
            clientsMap.clear();
        }
    }

    private void waitForRequest() {
        try {
            while (!Thread.currentThread().isInterrupted()) {
                Socket socket = serverSocket.accept();
                LOG.debug("Accept new socket " + socket);
                socketProcessor.submit(new SocketProcessorRunnable(socket));
            }
        } catch (IOException e) {
            onError(new ProxyCacheException("Error during waiting connection", e));
        }
    }

    private void processSocket(Socket socket) {
        try {
            GetRequest request = GetRequest.read(socket.getInputStream());
            LOG.debug("Request to cache proxy:" + request);
            String url = ProxyCacheUtils.decode(request.uri);
            if (pinger.isPingRequest(url)) {
                pinger.responseToPing(socket);
            } else {
                HttpProxyCacheServerClients clients = getClients(url);
                clients.processRequest(request, socket);
            }
        } catch (SocketException e) {
            // There is no way to determine that client closed connection http://stackoverflow.com/a/10241044/999458
            // So just to prevent log flooding don't log stacktrace
            LOG.debug("Closing socket… Socket is closed by client.");
        } catch (ProxyCacheException | IOException e) {
            onError(new ProxyCacheException("Error processing request", e));
        } finally {
            releaseSocket(socket);
            LOG.debug("Opened connections: " + getClientsCount());
        }
    }

    private HttpProxyCacheServerClients getClients(String url) throws ProxyCacheException {
        synchronized (clientsLock) {
            HttpProxyCacheServerClients clients = clientsMap.get(url);
            if (clients == null) {
                clients = new HttpProxyCacheServerClients(url, config);
                clientsMap.put(url, clients);
            }
            return clients;
        }
    }

    private int getClientsCount() {
        synchronized (clientsLock) {
            int count = 0;
            for (HttpProxyCacheServerClients clients : clientsMap.values()) {
                count += clients.getClientsCount();
            }
            return count;
        }
    }

    private void releaseSocket(Socket socket) {
        closeSocketInput(socket);
        closeSocketOutput(socket);
        closeSocket(socket);
    }

    private void closeSocketInput(Socket socket) {
        try {
            if (!socket.isInputShutdown()) {
                socket.shutdownInput();
            }
        } catch (SocketException e) {
            // There is no way to determine that client closed connection http://stackoverflow.com/a/10241044/999458
            // So just to prevent log flooding don't log stacktrace
            LOG.debug("Releasing input stream… Socket is closed by client.");
        } catch (IOException e) {
            onError(new ProxyCacheException("Error closing socket input stream", e));
        }
    }

    private void closeSocketOutput(Socket socket) {
        try {
            if (!socket.isOutputShutdown()) {
                socket.shutdownOutput();
            }
        } catch (IOException e) {
            LOG.warn("Failed to close socket on proxy side: {}. It seems client have already closed connection.", e.getMessage());
        }
    }

    private void closeSocket(Socket socket) {
        try {
            if (!socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            onError(new ProxyCacheException("Error closing socket", e));
        }
    }

    private void onError(Throwable e) {
        LOG.error("HttpProxyCacheServer error", e);
    }

    /**
     * Builder for {@link HttpProxyCacheServer}.
     */
    public static final class Builder {

        private static final long DEFAULT_MAX_SIZE = 512 * 1024 * 1024;

        private File cacheRoot;
        private FileNameGenerator fileNameGenerator;
        private DiskUsage diskUsage;
        private SourceInfoStorage sourceInfoStorage;
        private HeaderInjector headerInjector;

        public Builder(Context context) {
            this.sourceInfoStorage = SourceInfoStorageFactory.newSourceInfoStorage(context);
            this.cacheRoot = StorageUtils.getIndividualCacheDirectory(context);
            this.diskUsage = new TotalSizeLruDiskUsage(DEFAULT_MAX_SIZE);
            this.fileNameGenerator = new Md5FileNameGenerator();
            this.headerInjector = new EmptyHeadersInjector();
        }

        /**
         * Overrides default cache folder to be used for caching files.
         * <p>
         * By default AndroidVideoCache uses
         * '/Android/data/[app_package_name]/cache/video-cache/' if card is mounted and app has appropriate permission
         * or 'video-cache' subdirectory in default application's cache directory otherwise.
         * </p>
         * <b>Note</b> directory must be used <b>only</b> for AndroidVideoCache files.
         *
         * @param file a cache directory, can't be null.
         * @return a builder.
         */
        public Builder cacheDirectory(File file) {
            this.cacheRoot = checkNotNull(file);
            return this;
        }

        /**
         * Overrides default cache file name generator {@link Md5FileNameGenerator} .
         *
         * @param fileNameGenerator a new file name generator.
         * @return a builder.
         */
        public Builder fileNameGenerator(FileNameGenerator fileNameGenerator) {
            this.fileNameGenerator = checkNotNull(fileNameGenerator);
            return this;
        }

        /**
         * Sets max cache size in bytes.
         * <p>
         * All files that exceeds limit will be deleted using LRU strategy.
         * Default value is 512 Mb.
         * </p>
         * Note this method overrides result of calling {@link #maxCacheFilesCount(int)}
         *
         * @param maxSize max cache size in bytes.
         * @return a builder.
         */
        public Builder maxCacheSize(long maxSize) {
            this.diskUsage = new TotalSizeLruDiskUsage(maxSize);
            return this;
        }

        /**
         * Sets max cache files count.
         * All files that exceeds limit will be deleted using LRU strategy.
         * Note this method overrides result of calling {@link #maxCacheSize(long)}
         *
         * @param count max cache files count.
         * @return a builder.
         */
        public Builder maxCacheFilesCount(int count) {
            this.diskUsage = new TotalCountLruDiskUsage(count);
            return this;
        }

        /**
         * Set custom DiskUsage logic for handling when to keep or clean cache.
         *
         * @param diskUsage a disk usage strategy, cant be {@code null}.
         * @return a builder.
         */
        public Builder diskUsage(DiskUsage diskUsage) {
            this.diskUsage = checkNotNull(diskUsage);
            return this;
        }

        /**
         * Add headers along the request to the server
         *
         * @param headerInjector to inject header base on url
         * @return a builder
         */
        public Builder headerInjector(HeaderInjector headerInjector) {
            this.headerInjector = checkNotNull(headerInjector);
            return this;
        }

        /**
         * Builds new instance of {@link HttpProxyCacheServer}.
         *
         * @return proxy cache. Only single instance should be used across whole app.
         */
        public HttpProxyCacheServer build() {
            Config config = buildConfig();
            return new HttpProxyCacheServer(config,"127.0.0.1");
        }

        private Config buildConfig() {
            return new Config(cacheRoot, fileNameGenerator, diskUsage, sourceInfoStorage, headerInjector);
        }

    }

    private final class WaitRequestsRunnable implements Runnable {

        private final CountDownLatch startSignal;

        public WaitRequestsRunnable(CountDownLatch startSignal) {
            this.startSignal = startSignal;
        }

        @Override
        public void run() {
            startSignal.countDown();
            waitForRequest();
        }
    }

    private final class SocketProcessorRunnable implements Runnable {

        private final Socket socket;

        public SocketProcessorRunnable(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            processSocket(socket);
        }
    }
}

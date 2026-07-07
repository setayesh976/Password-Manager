import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.*;

/**
 * Password Manager - Single File Version
 * All classes combined: model, cipher, storage, generator, manager, UI.
 */
public class PasswordManager {

    // ══════════════════════════════════════════════════════════════════════════
    // MODEL
    // ══════════════════════════════════════════════════════════════════════════

    static class Password {
        private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
        private String id, service, username, encryptedPassword, category, notes, createdAt, updatedAt;

        public Password() {}

        public Password(String id, String service, String username,
                        String encryptedPassword, String category, String notes) {
            this.id = id; this.service = service; this.username = username;
            this.encryptedPassword = encryptedPassword; this.category = category; this.notes = notes;
            String now = LocalDateTime.now().format(FMT);
            this.createdAt = now; this.updatedAt = now;
        }

        public String getId()                  { return id; }
        public void   setId(String id)         { this.id = id; }
        public String getService()             { return service; }
        public void   setService(String s)     { this.service = s; }
        public String getUsername()            { return username; }
        public void   setUsername(String u)    { this.username = u; }
        public String getEncryptedPassword()   { return encryptedPassword; }
        public void   setEncryptedPassword(String p) { this.encryptedPassword = p; }
        public String getCategory()            { return category; }
        public void   setCategory(String c)    { this.category = c; }
        public String getNotes()               { return notes; }
        public void   setNotes(String n)       { this.notes = n; }
        public String getCreatedAt()           { return createdAt; }
        public void   setCreatedAt(String t)   { this.createdAt = t; }
        public String getUpdatedAt()           { return updatedAt; }
        public void   setUpdatedAt(String t)   { this.updatedAt = t; }
        public void   touchUpdated()           { this.updatedAt = LocalDateTime.now().format(FMT); }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // CIPHER (XOR + Base64)
    // ══════════════════════════════════════════════════════════════════════════

    static class Cipher {
        private final byte[] key;
        public Cipher(String masterKey) { this.key = masterKey.getBytes(); }

        public String encrypt(String plaintext) {
            return Base64.getEncoder().encodeToString(xor(plaintext.getBytes()));
        }

        public String decrypt(String ciphertext) {
            return new String(xor(Base64.getDecoder().decode(ciphertext)));
        }

        private byte[] xor(byte[] data) {
            byte[] out = new byte[data.length];
            for (int i = 0; i < data.length; i++) out[i] = (byte)(data[i] ^ key[i % key.length]);
            return out;
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // JSON STORAGE
    // ══════════════════════════════════════════════════════════════════════════

    static class JsonStorage {
        private final Path filePath;

        public JsonStorage(String dataDir) {
            Path dir = Paths.get(dataDir);
            try { Files.createDirectories(dir); } catch (IOException e) { /* ignore */ }
            this.filePath = dir.resolve("passwords.json");
        }

        public List<Password> loadAll() {
            if (!Files.exists(filePath)) return new ArrayList<>();
            try {
                return parseJson(new String(Files.readAllBytes(filePath)));
            } catch (IOException e) { return new ArrayList<>(); }
        }

        public boolean saveAll(List<Password> passwords) {
            try {
                Files.write(filePath, toJson(passwords).getBytes(),
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                return true;
            } catch (IOException e) { return false; }
        }

        private String toJson(List<Password> list) {
            StringBuilder sb = new StringBuilder("[\n");
            for (int i = 0; i < list.size(); i++) {
                Password p = list.get(i);
                sb.append("  {\n")
                  .append(field("id", p.getId())).append(field("service", p.getService()))
                  .append(field("username", p.getUsername())).append(field("encryptedPassword", p.getEncryptedPassword()))
                  .append(field("category", p.getCategory())).append(field("notes", p.getNotes()))
                  .append(field("createdAt", p.getCreatedAt())).append(fieldLast("updatedAt", p.getUpdatedAt()))
                  .append("  }");
                if (i < list.size() - 1) sb.append(",");
                sb.append("\n");
            }
            return sb.append("]").toString();
        }

        private String field(String k, String v)     { return String.format("    \"%s\": \"%s\",\n", k, escape(v)); }
        private String fieldLast(String k, String v) { return String.format("    \"%s\": \"%s\"\n",  k, escape(v)); }
        private String escape(String s) {
            if (s == null) return "";
            return s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n");
        }

        private List<Password> parseJson(String json) {
            List<Password> result = new ArrayList<>();
            for (String obj : json.split("\\{")) {
                if (!obj.contains("\"id\"")) continue;
                Password p = new Password();
                p.setId(extractValue(obj, "id")); p.setService(extractValue(obj, "service"));
                p.setUsername(extractValue(obj, "username")); p.setEncryptedPassword(extractValue(obj, "encryptedPassword"));
                p.setCategory(extractValue(obj, "category")); p.setNotes(extractValue(obj, "notes"));
                p.setCreatedAt(extractValue(obj, "createdAt")); p.setUpdatedAt(extractValue(obj, "updatedAt"));
                if (p.getId() != null && !p.getId().isEmpty()) result.add(p);
            }
            return result;
        }

        private String extractValue(String obj, String key) {
            String search = "\"" + key + "\": \"";
            int start = obj.indexOf(search);
            if (start == -1) return "";
            start += search.length();
            int end = obj.indexOf("\"", start);
            if (end == -1) return "";
            return obj.substring(start, end).replace("\\\"","\"").replace("\\\\","\\");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // PASSWORD GENERATOR
    // ══════════════════════════════════════════════════════════════════════════

    static class PasswordGenerator {
        private static final String LOWER   = "abcdefghijklmnopqrstuvwxyz";
        private static final String UPPER   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private static final String DIGITS  = "0123456789";
        private static final String SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        private final SecureRandom random   = new SecureRandom();

        public String generate(int length, boolean upper, boolean digits, boolean symbols) {
            if (length < 4) length = 4;
            StringBuilder pool = new StringBuilder(LOWER);
            List<Character> guaranteed = new ArrayList<>();
            guaranteed.add(randomFrom(LOWER));
            if (upper)   { pool.append(UPPER);   guaranteed.add(randomFrom(UPPER)); }
            if (digits)  { pool.append(DIGITS);  guaranteed.add(randomFrom(DIGITS)); }
            if (symbols) { pool.append(SYMBOLS); guaranteed.add(randomFrom(SYMBOLS)); }
            char[] pw = new char[length];
            for (int i = 0; i < guaranteed.size(); i++) pw[i] = guaranteed.get(i);
            String poolStr = pool.toString();
            for (int i = guaranteed.size(); i < length; i++) pw[i] = poolStr.charAt(random.nextInt(poolStr.length()));
            shuffle(pw);
            return new String(pw);
        }

        private char randomFrom(String s) { return s.charAt(random.nextInt(s.length())); }
        private void shuffle(char[] arr) {
            for (int i = arr.length - 1; i > 0; i--) {
                int j = random.nextInt(i + 1); char t = arr[i]; arr[i] = arr[j]; arr[j] = t;
            }
        }

        public StrengthResult analyzeStrength(String pw) {
            if (pw == null || pw.isEmpty()) return new StrengthResult("None", 0, "Empty password.");
            int score = 0; List<String> tips = new ArrayList<>();
            int len = pw.length();
            if (len >= 8) score++; if (len >= 12) score++; if (len >= 16) score++;
            if (len < 8) tips.add("Use at least 8 characters");
            boolean hasL = pw.chars().anyMatch(Character::isLowerCase);
            boolean hasU = pw.chars().anyMatch(Character::isUpperCase);
            boolean hasD = pw.chars().anyMatch(Character::isDigit);
            boolean hasS = pw.chars().anyMatch(c -> SYMBOLS.indexOf(c) >= 0);
            if (hasL) score++; if (hasU) score++; if (hasD) score++; if (hasS) score += 2;
            if (!hasU) tips.add("Add uppercase letters");
            if (!hasD) tips.add("Add numbers");
            if (!hasS) tips.add("Add special characters");
            int cs = (hasL?26:0)+(hasU?26:0)+(hasD?10:0)+(hasS?32:0);
            int entropy = cs > 0 ? (int)(len * (Math.log(cs) / Math.log(2))) : 0;
            String level = score >= 7 ? "Very Strong" : score >= 5 ? "Strong" : score >= 3 ? "Moderate" : score >= 1 ? "Weak" : "Very Weak";
            String fb = tips.isEmpty() ? "Excellent password!" : String.join("; ", tips);
            return new StrengthResult(level, entropy, fb);
        }

        static class StrengthResult {
            public final String level, feedback;
            public final int entropyBits;
            public StrengthResult(String level, int entropyBits, String feedback) {
                this.level = level; this.entropyBits = entropyBits; this.feedback = feedback;
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MANAGER (CRUD)
    // ══════════════════════════════════════════════════════════════════════════

    static class VaultManager {
        private final JsonStorage storage;
        private final Cipher      cipher;
        private final List<Password> cache;

        public VaultManager(String dataDir, String masterKey) {
            this.storage = new JsonStorage(dataDir);
            this.cipher  = new Cipher(masterKey);
            this.cache   = new ArrayList<>(storage.loadAll());
        }

        public boolean add(String service, String username, String plain, String category, String notes) {
            if (service == null || service.isBlank() || plain == null || plain.isBlank()) return false;
            String id = "pm-" + Long.toHexString(System.currentTimeMillis()) + "-" + Integer.toHexString(new Random().nextInt(0xFFFF));
            cache.add(new Password(id, service.trim(), username.trim(), cipher.encrypt(plain), category.trim(), notes.trim()));
            return storage.saveAll(cache);
        }

        public Optional<Password> findById(String id) { return cache.stream().filter(p -> p.getId().equals(id)).findFirst(); }

        public List<Password> search(String q) {
            if (q == null || q.isBlank()) return new ArrayList<>(cache);
            String lq = q.toLowerCase();
            return cache.stream().filter(p ->
                p.getService().toLowerCase().contains(lq) || p.getUsername().toLowerCase().contains(lq) ||
                p.getCategory().toLowerCase().contains(lq) || p.getNotes().toLowerCase().contains(lq)
            ).collect(Collectors.toList());
        }

        public List<Password> getByCategory(String cat) {
            return cache.stream().filter(p -> p.getCategory().equalsIgnoreCase(cat)).collect(Collectors.toList());
        }

        public boolean update(String id, String service, String username, String plain, String category, String notes) {
            Optional<Password> opt = findById(id);
            if (opt.isEmpty()) return false;
            Password p = opt.get();
            if (service  != null && !service.isBlank())  p.setService(service.trim());
            if (username != null && !username.isBlank()) p.setUsername(username.trim());
            if (plain    != null && !plain.isBlank())    p.setEncryptedPassword(cipher.encrypt(plain));
            if (category != null && !category.isBlank()) p.setCategory(category.trim());
            if (notes    != null)                         p.setNotes(notes.trim());
            p.touchUpdated();
            return storage.saveAll(cache);
        }

        public boolean delete(String id) {
            boolean removed = cache.removeIf(p -> p.getId().equals(id));
            return removed && storage.saveAll(cache);
        }

        public String reveal(String id) { return findById(id).map(p -> cipher.decrypt(p.getEncryptedPassword())).orElse(null); }
        public List<Password> getAll()  { return Collections.unmodifiableList(cache); }
        public int count()              { return cache.size(); }
        public Set<String> getCategories() {
            return cache.stream().map(Password::getCategory).filter(c -> c != null && !c.isBlank())
                        .collect(Collectors.toCollection(TreeSet::new));
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // CONSOLE UI
    // ══════════════════════════════════════════════════════════════════════════

    static class ConsoleUI {
        private static final String R="\033[0m",BOLD="\033[1m",DIM="\033[2m",
            RED="\033[91m",GREEN="\033[92m",YELLOW="\033[93m",
            BLUE="\033[94m",CYAN="\033[96m",MAGENTA="\033[95m";

        private final Scanner scanner = new Scanner(System.in);
        private final VaultManager manager;
        private final PasswordGenerator gen = new PasswordGenerator();

        public ConsoleUI(VaultManager manager) { this.manager = manager; }

        public void run() {
            printBanner();
            boolean running = true;
            while (running) {
                printMenu();
                switch (prompt("Choice").trim()) {
                    case "1" -> addPassword();
                    case "2" -> listPasswords();
                    case "3" -> searchPasswords();
                    case "4" -> viewPassword();
                    case "5" -> editPassword();
                    case "6" -> deletePassword();
                    case "7" -> generatePassword();
                    case "8" -> showCategories();
                    case "9" -> { println(CYAN+"\n  Goodbye! 👋"+R); running = false; }
                    default  -> warn("Invalid option. Choose 1–9.");
                }
            }
        }

        private void addPassword() {
            header("ADD NEW PASSWORD");
            String service  = requireInput("Service / Website");
            String username = prompt("Username / Email");
            String passIn   = prompt("Password (blank to generate)");
            String finalPass;
            if (passIn.isBlank()) {
                finalPass = gen.generate(16, true, true, true);
                println(GREEN+"  Generated: "+BOLD+finalPass+R);
            } else {
                finalPass = passIn;
                PasswordGenerator.StrengthResult sr = gen.analyzeStrength(finalPass);
                println("  Strength: "+strengthColor(sr.level)+sr.level+R+" ["+sr.entropyBits+" bits]  "+DIM+sr.feedback+R);
            }
            String category = prompt("Category [default: General]");
            if (category.isBlank()) category = "General";
            String notes = prompt("Notes (optional)");
            if (manager.add(service, username, finalPass, category, notes))
                success("Saved! Total entries: " + manager.count());
            else error("Failed to save.");
        }

        private void listPasswords() {
            header("ALL PASSWORDS  (" + manager.count() + " entries)");
            List<Password> all = manager.getAll();
            if (all.isEmpty()) { println(DIM+"  No passwords stored yet."+R); return; }
            printTable(all);
        }

        private void searchPasswords() {
            header("SEARCH");
            String q = requireInput("Search term");
            List<Password> results = manager.search(q);
            println("  " + results.size() + " result(s):\n");
            if (results.isEmpty()) println(DIM+"  No matches found."+R);
            else printTable(results);
        }

        private void viewPassword() {
            header("VIEW PASSWORD");
            String id = requireInput("Entry ID");
            Optional<Password> opt = manager.findById(id);
            if (opt.isEmpty()) { error("Not found: " + id); return; }
            Password p = opt.get();
            println("\n"+div());
            row("ID", p.getId()); row("Service", p.getService()); row("Username", p.getUsername());
            row("Category", p.getCategory()); row("Notes", p.getNotes());
            row("Created", p.getCreatedAt()); row("Updated", p.getUpdatedAt());
            println(div());
            if (prompt("Reveal password? (y/N)").equalsIgnoreCase("y")) {
                String plain = manager.reveal(id);
                println(GREEN+BOLD+"\n  Password: "+plain+R);
                PasswordGenerator.StrengthResult sr = gen.analyzeStrength(plain);
                println("  Strength: "+strengthColor(sr.level)+sr.level+R+" ["+sr.entropyBits+" bits]");
            }
        }

        private void editPassword() {
            header("EDIT PASSWORD");
            String id = requireInput("Entry ID");
            if (manager.findById(id).isEmpty()) { error("Not found."); return; }
            println(DIM+"  (Enter to keep current value)"+R);
            String service  = prompt("New service");
            String username = prompt("New username");
            String passIn   = prompt("New password (or 'gen')");
            String finalPass = null;
            if (passIn.equalsIgnoreCase("gen")) {
                finalPass = gen.generate(16, true, true, true);
                println(GREEN+"  Generated: "+BOLD+finalPass+R);
            } else if (!passIn.isBlank()) {
                finalPass = passIn;
            }
            String category = prompt("New category");
            String notes    = prompt("New notes");
            if (manager.update(id,
                service.isBlank() ? null : service,
                username.isBlank() ? null : username,
                finalPass,
                category.isBlank() ? null : category,
                notes.isBlank() ? null : notes))
                success("Updated.");
            else error("Update failed.");
        }

        private void deletePassword() {
            header("DELETE PASSWORD");
            String id = requireInput("Entry ID");
            Optional<Password> opt = manager.findById(id);
            if (opt.isEmpty()) { error("Not found."); return; }
            println(YELLOW+"\n  Service: "+opt.get().getService()+R);
            if (requireInput("Type DELETE to confirm").equals("DELETE")) {
                if (manager.delete(id)) success("Deleted.");
                else error("Failed.");
            } else warn("Cancelled.");
        }

        private void generatePassword() {
            header("PASSWORD GENERATOR");
            String lenStr = prompt("Length [default 16]");
            int length;
            try { length = lenStr.isBlank() ? 16 : Integer.parseInt(lenStr); }
            catch (NumberFormatException e) { length = 16; }
            length = Math.max(4, Math.min(length, 128));
            boolean upper   = !prompt("Include uppercase? (Y/n)").equalsIgnoreCase("n");
            boolean digits  = !prompt("Include digits?    (Y/n)").equalsIgnoreCase("n");
            boolean symbols = !prompt("Include symbols?   (Y/n)").equalsIgnoreCase("n");
            println("\n  Generating 5 passwords:\n");
            for (int i = 1; i <= 5; i++) {
                String pw = gen.generate(length, upper, digits, symbols);
                PasswordGenerator.StrengthResult sr = gen.analyzeStrength(pw);
                println(String.format("  %d.  "+BOLD+"%-32s"+R+"  %s%s%s  [%d bits]",
                        i, pw, strengthColor(sr.level), sr.level, R, sr.entropyBits));
            }
            println("");
        }

        private void showCategories() {
            header("CATEGORIES");
            Set<String> cats = manager.getCategories();
            if (cats.isEmpty()) { println(DIM+"  No categories yet."+R); return; }
            for (String cat : cats) {
                List<Password> entries = manager.getByCategory(cat);
                println(CYAN+"  ▸ "+BOLD+cat+R+"  ("+entries.size()+" entries)");
                for (Password p : entries)
                    println(String.format("      "+DIM+"[%s]"+R+"  %-25s  %s", p.getId(), p.getService(), p.getUsername()));
                println("");
            }
        }

        private void printTable(List<Password> list) {
            println(String.format(DIM+"  %-18s  %-22s  %-18s  %-12s"+R, "ID","Service","Username","Category"));
            println(div());
            for (Password p : list)
                println(String.format("  "+CYAN+"%-18s"+R+"  "+BOLD+"%-22s"+R+"  %-18s  "+DIM+"%-12s"+R,
                        p.getId(), trunc(p.getService(),22), trunc(p.getUsername(),18), p.getCategory()));
            println("");
        }

        private void printMenu() {
            println("\n"+div());
            println(CYAN+BOLD+"  ☕ PASSWORD MANAGER"+R+DIM+"  ["+manager.count()+" stored]"+R);
            println(div());
            println(GREEN+"  [1]"+R+" Add password");
            println(BLUE+"  [2]"+R+" List all");
            println(YELLOW+"  [3]"+R+" Search");
            println(CYAN+"  [4]"+R+" View / reveal");
            println(MAGENTA+"  [5]"+R+" Edit");
            println(RED+"  [6]"+R+" Delete");
            println(GREEN+"  [7]"+R+" Generate password");
            println(BLUE+"  [8]"+R+" Browse categories");
            println(DIM+"  [9]  Quit"+R);
            println(div());
        }

        private void printBanner() {
            println(CYAN+BOLD);
            println("  ╔═══════════════════════════════════╗");
            println("  ║  ☕  Java Password Manager  v1.0  ║");
            println("  ╚═══════════════════════════════════╝");
            println(R);
        }

        private void header(String t) { println("\n"+BOLD+CYAN+"  ── "+t+" ──"+R+"\n"); }
        private void success(String m){ println(GREEN+"\n  ✓ "+m+R); }
        private void error(String m)  { println(RED+"\n  ✗ "+m+R); }
        private void warn(String m)   { println(YELLOW+"\n  ⚠ "+m+R); }
        private void println(String s){ System.out.println(s); }
        private void row(String l, String v){ System.out.println(String.format("  "+DIM+"%-10s"+R+"  %s", l+":", v==null?"":v)); }
        private String div()          { return DIM+"  "+"─".repeat(68)+R; }
        private String trunc(String s, int max){ if(s==null)return""; return s.length()<=max?s:s.substring(0,max-1)+"…"; }
        private String prompt(String label) { System.out.print("  "+DIM+label+": "+R); return scanner.nextLine(); }
        private String requireInput(String label) {
            String v;
            do { v = prompt(label); if(v.isBlank()) warn("Required field."); } while(v.isBlank());
            return v.trim();
        }
        private String strengthColor(String level) {
            return switch(level) {
                case "Very Strong" -> GREEN+BOLD;
                case "Strong"      -> GREEN;
                case "Moderate"    -> YELLOW;
                default            -> RED;
            };
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // ENTRY POINT
    // ══════════════════════════════════════════════════════════════════════════

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("\033[96m\033[1m");
        System.out.println("  ╔═══════════════════════════════════╗");
        System.out.println("  ║  ☕  Java Password Manager  v1.0  ║");
        System.out.println("  ╚═══════════════════════════════════╝");
        System.out.println("\033[0m");
        System.out.print("  \033[2mEnter master key to unlock vault: \033[0m");
        String masterKey = scanner.nextLine().trim();
        if (masterKey.isEmpty()) {
            System.out.println("\033[91m  Master key cannot be empty. Exiting.\033[0m");
            System.exit(1);
        }
        new ConsoleUI(new VaultManager("data", masterKey)).run();
    }
}

public class SecurityUtils {
    public static boolean verifyChecksum(String hash) {
        return hash != null && hash.length() == 64;
    }
}

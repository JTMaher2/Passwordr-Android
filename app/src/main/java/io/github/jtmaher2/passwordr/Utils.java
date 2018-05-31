package io.github.jtmaher2.passwordr;

public class Utils {
    private static final int GEN_PASSWORD_LENGTH = 20;

    // generates a PASSWORD_LEN long password with a certain number of letters, numbers, and symbols
    public static String generatePassword() {
        String string = "abcdefghijklmnopqrstuvwxyz"; //to upper
        String numeric = "0123456789";
        String punctuation = "!@#$%^&*()_+~`|}{[]\\:;?><,./-=";
        String password = "";
        String character = "";

        while( password.length()<GEN_PASSWORD_LENGTH ) {
            double entity1 = Math.ceil(string.length() * Math.random()*Math.random());
            double entity2 = Math.ceil(numeric.length() * Math.random()*Math.random());
            double entity3 = Math.ceil(punctuation.length() * Math.random()*Math.random());
            char hold = string.charAt( (int)entity1 );
            hold = (entity1%2==0)?(Character.toUpperCase(hold)):(hold);
            character += hold;
            character += numeric.charAt( (int)entity2 );
            character += punctuation.charAt( (int)entity3 );
            password = character;
        }

        return password;
    }
}

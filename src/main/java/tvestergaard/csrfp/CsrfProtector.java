package tvestergaard.csrfp;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedList;

/**
 * Generates and verifies Base64 tokens used to protect against Cross Site Request Forgery. Uses the {@link SecureRandom}
 * number generator when generating the tokens.
 */
public class CsrfProtector
{

    /**
     * The entropy of the tokens generated by the {@link CsrfProtector} in bytes.
     */
    private final int entropy;

    /**
     * The maximum number of tokens that can be registered with the {@link CsrfProtector}.
     */
    private final int maximum;

    /**
     * The tokens registered with the {@link CsrfProtector}.
     */
    private final LinkedList<String> tokens = new LinkedList<>();

    /**
     * The source of randomness used when generating new tokens.
     */
    private static final SecureRandom random = new SecureRandom();

    /**
     * Encodes random bytes into Base64 suitable for use in urls.
     */
    private static final Base64.Encoder encoder = Base64.getUrlEncoder();

    /**
     * Creates a new {@link CsrfProtector}.
     *
     * @param entropy The entropy of the tokens generated by the {@link CsrfProtector} in bytes.
     * @param maximum The maximum number of tokens that can be registered with the {@link CsrfProtector}.
     */
    public CsrfProtector(final int entropy, final int maximum)
    {
        this.entropy = entropy;
        this.maximum = maximum;
    }

    /**
     * Creates a new {@link CsrfProtector}. The maximum number of tokens that can be registered with the
     * {@link CsrfProtector} is set to 10.
     *
     * @param entropy The entropy of the tokens generated by the {@link CsrfProtector} in bytes.
     */
    public CsrfProtector(final int entropy)
    {
        this(entropy, 10);
    }

    /**
     * Creates a new {@link CsrfProtector}. The entropy of the tokens generated by the {@link CsrfProtector} in bytes
     * is set to 32. The maximum number of tokens that can be registered with the {@link CsrfProtector} is set to 10.
     */
    public CsrfProtector()
    {
        this(32);
    }

    /**
     * Generates and registers a token with the provided {@code entropy}.
     *
     * @param entropy The entropy of the token to generate in bytes.
     * @return The newly generated token.
     */
    public String generate(int entropy)
    {
        byte[] bytes = new byte[entropy];
        random.nextBytes(bytes);
        String token = encoder.encodeToString(bytes);

        if (tokens.size() == maximum)
            tokens.removeFirst();
        tokens.push(token);

        return token;
    }

    /**
     * Generates and registers a token with the configured entropy in bytes.
     *
     * @return The newly generated token.
     */
    public String generate()
    {
        return generate(entropy);
    }

    /**
     * Verifies that the provided {@code token} is registered with the {@link CsrfProtector}.
     *
     * @param token  The token to verify.
     * @param remove Whether or not the remove the token afterwards.
     * @return {@code true} when the token could be verified.
     */
    public boolean verify(String token, boolean remove)
    {
        Iterator<String> iterator = tokens.iterator();
        while (iterator.hasNext()) {
            if (token.equals(iterator.next())) {
                if (remove)
                    iterator.remove();
                return true;
            }
        }

        return false;
    }

    /**
     * Verifies that the provided {@code token} is registered with the {@link CsrfProtector}. Removes the token afterwards.
     *
     * @param token The token to verify.
     * @return {@code true} when the token could be verified.
     */
    public boolean verify(String token)
    {
        return verify(token, true);
    }

    /**
     * Returns the number of tokens in the {@link CsrfProtector}.
     *
     * @return The number of tokens in the {@link CsrfProtector}.
     */
    public int size()
    {
        return tokens.size();
    }

    /**
     * Removes the tokens registered with the {@link CsrfProtector}.
     */
    public void clear()
    {
        tokens.clear();
    }

    /**
     * Checks if there are no tokens registered with the {@link CsrfProtector}.
     *
     * @return {@code true} if there are no tokens registered with the {@link CsrfProtector}.
     */
    public boolean isEmpty()
    {
        return tokens.isEmpty();
    }

    /**
     * Returns the entropy of the tokens generated by the {@link CsrfProtector} in bytes.
     *
     * @return The entropy of the tokens generated by the {@link CsrfProtector} in bytes.
     */
    public int getEntropy()
    {
        return this.entropy;
    }

    /**
     * Returns the maximum number of tokens that can be registered with the {@link CsrfProtector}.
     *
     * @return The maximum number of tokens that can be registered with the {@link CsrfProtector}.
     */
    public int getMaximum()
    {
        return this.maximum;
    }
}

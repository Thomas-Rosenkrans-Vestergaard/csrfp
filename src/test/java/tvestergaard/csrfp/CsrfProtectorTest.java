package tvestergaard.csrfp;

import org.junit.Test;

import static org.junit.Assert.*;

public class CsrfProtectorTest
{

    @Test
    public void generate() throws Exception
    {
        for (int entropy = 6; entropy < 128; entropy += 5) {
            CsrfProtector protector = new CsrfProtector(entropy, 10);
            int           expected  = (entropy * 8 / 6 + 3) / 4 * 4;
            String        token     = protector.generate(entropy);
            assertEquals(expected, token.length());
            assertTrue(protector.verify(token, true));
            assertTrue(protector.isEmpty());
        }
    }

    @Test
    public void generateWithEntropy() throws Exception
    {
        CsrfProtector protector = new CsrfProtector(0, 10);
        for (int entropy = 6; entropy < 128; entropy += 5) {
            int    expected = (entropy * 8 / 6 + 3) / 4 * 4;
            String token    = protector.generate(entropy);
            assertEquals(expected, token.length());
            assertTrue(protector.verify(token, true));
        }

        assertTrue(protector.isEmpty());
    }

    @Test
    public void verify() throws Exception
    {
        for (int entropy = 6; entropy < 128; entropy += 5) {
            CsrfProtector protector = new CsrfProtector(entropy, 10);
            String        token     = protector.generate(entropy);
            assertFalse(protector.verify(token + "_", false));
            assertFalse(protector.isEmpty());
            assertTrue(protector.verify(token));
            assertTrue(protector.isEmpty());
        }
    }

    @Test
    public void size() throws Exception
    {
        CsrfProtector protector = new CsrfProtector();
        assertEquals(0, protector.size());
        String token = protector.generate(1);
        assertEquals(1, protector.size());
        assertTrue(protector.verify(token, true));
        assertEquals(0, protector.size());
    }

    @Test
    public void clear() throws Exception
    {
        CsrfProtector protector = new CsrfProtector();
        assertTrue(protector.isEmpty());
        protector.generate(1);
        assertFalse(protector.isEmpty());
        protector.clear();
        assertTrue(protector.isEmpty());
    }

    @Test
    public void isEmpty() throws Exception
    {
        CsrfProtector protector = new CsrfProtector();
        assertTrue(protector.isEmpty());
        String token = protector.generate(1);
        assertFalse(protector.isEmpty());
        assertTrue(protector.verify(token, true));
        assertTrue(protector.isEmpty());
    }

    @Test
    public void getEntropy() throws Exception
    {
        for (int expected = 0; expected < 10; expected++) {
            CsrfProtector protector = new CsrfProtector(expected);
            assertEquals(expected, protector.getEntropy());
        }
    }

    @Test
    public void getMaximum() throws Exception
    {
        for (int expected = 0; expected < 10; expected++) {
            CsrfProtector protector = new CsrfProtector(0, expected);
            assertEquals(0, protector.getEntropy());
            assertEquals(expected, protector.getMaximum());
        }
    }
}
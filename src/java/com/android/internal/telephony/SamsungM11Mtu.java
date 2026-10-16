package com.android.internal.telephony;

/**
 * Decodes a packed MTU value returned by the Samsung M11 legacy IWLAN radio path.
 *
 * <p>The low 16 bits carry the IPv4 MTU and the high 16 bits carry the IPv6 MTU.
 * The legacy DataCallResponse MTU is the larger of the two family-specific values.
 */
final class SamsungM11Mtu {
    private SamsungM11Mtu() {}

    /** Returns values in {@code [legacy, IPv4, IPv6]} order. */
    static int[] decodeLegacyMtu(int rawMtu) {
        if (rawMtu <= 0xffff) {
            // Ordinary scalar MTUs and sentinels retain RILUtils' old behavior.
            return new int[] {rawMtu, rawMtu, rawMtu};
        }

        int mtuV4 = rawMtu & 0xffff;
        int mtuV6 = rawMtu >>> 16;
        if (!isValidFamilyMtu(mtuV4, 68, 10_000)
                || !isValidFamilyMtu(mtuV6, 1_280, 10_000)
                || (mtuV4 == 0 && mtuV6 == 0)) {
            // Only normalize values that plausibly encode valid per-family MTUs.
            return new int[] {rawMtu, rawMtu, rawMtu};
        }
        return new int[] {Math.max(mtuV4, mtuV6), mtuV4, mtuV6};
    }

    private static boolean isValidFamilyMtu(int mtu, int minimum, int maximum) {
        return mtu == 0 || (mtu >= minimum && mtu <= maximum);
    }
}

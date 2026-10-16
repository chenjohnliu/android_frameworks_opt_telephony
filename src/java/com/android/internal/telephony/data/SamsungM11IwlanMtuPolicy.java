package com.android.internal.telephony.data;

/**
 * Pure policy for the Samsung M11 legacy IWLAN route MTU workaround.
 *
 * <p>The caller supplies already-normalized, positive IPv4 and IPv6 MTUs. This class never
 * decodes a modem's packed MTU field and never performs Android or interface I/O.
 */
final class SamsungM11IwlanMtuPolicy {
    static final int IWLAN_CAP = 1400;
    private static final int MIN_V4 = 68;
    private static final int MIN_V6 = 1280;
    private static final int MAX_MTU = 10_000;

    private String mOwnedInterface;
    private int mOwnedIfindex;
    private int mOwnedCid;
    private int mBaselineKernelMtu;
    private int mIssuedLinkMtu;
    private Result mLastSafeResult;
    private boolean mRestorePending;
    private int mPendingObservedKernelMtu;

    /** Immutable policy output. Values are the route MTUs and legacy LinkProperties MTU. */
    static final class Result {
        final int routeMtuV4;
        final int routeMtuV6;
        final int linkMtu;
        final boolean changed;
        final boolean heldForUnknownKernel;

        Result(int v4, int v6, int link, boolean changed, boolean held) {
            routeMtuV4 = v4;
            routeMtuV6 = v6;
            linkMtu = link;
            this.changed = changed;
            heldForUnknownKernel = held;
        }
    }

    /**
     * Applies one event. {@code scope} means every static restriction (device, legacy mode,
     * operator/phone match, valid subscription, IMS-only APN, and WWAN) has passed. IWLAN is
     * specifically the current MMTEL registration technology, not a preferred transport.
     *
     * <p>If {@code interfaceKnown} is false, interfaceName and cid still identify the current
     * bearer when available; a matching owned bearer retains its last safe result. An unknown
     * index is never treated as a valid identity and cannot acquire a new lease.
     */
    Result evaluate(boolean scope, boolean iwlan, String interfaceName, int ifindex, int cid,
            boolean interfaceKnown, int kernelMtu, int reportedV4, int reportedV6) {
        Result original = new Result(reportedV4, reportedV6,
                Math.max(reportedV4, reportedV6), false, false);
        boolean validReported = validV4(reportedV4) && validV6(reportedV6);

        if (isOwnedBearer(interfaceName, cid) && !interfaceKnown) {
            if (mLastSafeResult != null) {
                return held(mLastSafeResult);
            }
            return original;
        }

        boolean validIdentity = interfaceKnown && interfaceName != null
                && !interfaceName.isEmpty() && ifindex > 0 && cid >= 0;
        boolean sameIdentity = validIdentity && matchesOwned(interfaceName, ifindex, cid);
        boolean hadOwner = mOwnedInterface != null;

        // A different, known bearer cannot inherit or restore the previous bearer’s lease.
        if (hadOwner && !sameIdentity && (validIdentity || !isOwnedBearer(interfaceName, cid))) {
            clearLease();
            hadOwner = false;
        }

        if (!validReported) {
            // Invalid typed MTUs never create a cap or justify restoring a previous baseline.
            if (hadOwner && sameIdentity && kernelMtu == mIssuedLinkMtu) {
                Result held = mLastSafeResult;
                if (held != null) return held(held);
            }
            return original;
        }

        boolean validKernel = validKernel(kernelMtu);
        if (!validKernel) {
            if (hadOwner && sameIdentity && mLastSafeResult != null) {
                return held(mLastSafeResult);
            }
            return original;
        }

        // Both effective family MTUs are supplied by the caller. Do not emit an IPv6 route MTU
        // below its protocol minimum, even when an unusual interface snapshot reports it.
        if (kernelMtu < MIN_V6) {
            if (sameIdentity && kernelMtu != mIssuedLinkMtu) clearLease();
            return original;
        }

        int reportedMax = Math.max(reportedV4, reportedV6);
        boolean externalChangeOnOwnedBearer = false;
        boolean completedRestore = false;
        if (sameIdentity && mRestorePending) {
            if (scope && iwlan) {
                // Re-entering IWLAN before the requested restore is observed keeps the original
                // baseline and resumes the cap lease from the current observed value.
                if (kernelMtu == mPendingObservedKernelMtu || kernelMtu == mIssuedLinkMtu) {
                    mRestorePending = false;
                    mIssuedLinkMtu = kernelMtu;
                } else {
                    clearLease();
                    hadOwner = false;
                    sameIdentity = false;
                }
            } else if (kernelMtu == mPendingObservedKernelMtu) {
                int target = Math.min(mBaselineKernelMtu, reportedMax);
                Result pending = new Result(Math.min(reportedV4, target),
                        Math.min(reportedV6, target), target, true, false);
                if (target == kernelMtu) {
                    clearLease();
                    return pending;
                }
                mIssuedLinkMtu = target;
                mLastSafeResult = pending;
                return pending;
            } else if (kernelMtu == mIssuedLinkMtu) {
                clearLease();
                hadOwner = false;
                sameIdentity = false;
                completedRestore = true;
            } else {
                clearLease();
                hadOwner = false;
                sameIdentity = false;
                externalChangeOnOwnedBearer = true;
            }
        } else {
            externalChangeOnOwnedBearer = sameIdentity && kernelMtu != mIssuedLinkMtu;
        }
        if (externalChangeOnOwnedBearer) {
            // An external kernel change revokes our ownership. It is authoritative and is never
            // raised, including when it is a smaller native value such as 1310.
            clearLease();
            hadOwner = false;
            sameIdentity = false;
        }

        if (scope && iwlan && validIdentity) {
            int normalLink = Math.min(reportedMax, kernelMtu);
            int link = Math.min(normalLink, IWLAN_CAP);
            int v4 = Math.min(reportedV4, link);
            int v6 = Math.min(reportedV6, link);
            if (sameIdentity) {
                // Keep the original baseline while the observed interface matches the last
                // target we issued. The newly computed target may be unchanged.
                mRestorePending = false;
                mIssuedLinkMtu = link;
            } else if (kernelMtu > link) {
                mOwnedInterface = interfaceName;
                mOwnedIfindex = ifindex;
                mOwnedCid = cid;
                mBaselineKernelMtu = kernelMtu;
                mIssuedLinkMtu = link;
            }
            Result result = new Result(v4, v6, link, true, false);
            if (mOwnedInterface != null && matchesOwned(interfaceName, ifindex, cid)) {
                mLastSafeResult = result;
            }
            return result;
        }

        if (hadOwner && sameIdentity) {
            // Leaving scope restores only a baseline still owned by us, and only up to the
            // currently reported MTU. The current kernel value must still equal our target.
            int restored = Math.min(mBaselineKernelMtu, reportedMax);
            int link = restored;
            int v4 = Math.min(reportedV4, link);
            int v6 = Math.min(reportedV6, link);
            Result restore = new Result(v4, v6, link, true, false);
            if (link != kernelMtu) {
                // LinkProperties carries an issued restore target. Keep it pending across
                // subsequent data-network events until the interface reports that value.
                mRestorePending = true;
                mPendingObservedKernelMtu = kernelMtu;
                mIssuedLinkMtu = link;
                mLastSafeResult = restore;
            } else {
                clearLease();
            }
            return restore;
        }

        if (externalChangeOnOwnedBearer || completedRestore) {
            int link = Math.min(reportedMax, kernelMtu);
            return new Result(Math.min(reportedV4, link), Math.min(reportedV6, link), link,
                    true, false);
        }

        // For eligible M11 IMS outside IWLAN, respect a smaller observed kernel MTU. All other
        // profiles/devices retain the original route and legacy MTUs.
        if (scope && validIdentity) {
            int link = Math.min(reportedMax, kernelMtu);
            return new Result(Math.min(reportedV4, link), Math.min(reportedV6, link), link,
                    link != reportedMax, false);
        }
        return original;
    }

    void reset() {
        clearLease();
    }

    boolean hasLease() {
        return mOwnedInterface != null;
    }

    private Result held(Result result) {
        return new Result(result.routeMtuV4, result.routeMtuV6, result.linkMtu,
                result.changed, true);
    }

    private boolean isOwnedBearer(String interfaceName, int cid) {
        return mOwnedInterface != null && mOwnedInterface.equals(interfaceName)
                && mOwnedCid == cid;
    }

    private boolean matchesOwned(String interfaceName, int ifindex, int cid) {
        return mOwnedInterface != null && mOwnedInterface.equals(interfaceName)
                && mOwnedIfindex == ifindex && mOwnedCid == cid;
    }

    private void clearLease() {
        mOwnedInterface = null;
        mOwnedIfindex = 0;
        mOwnedCid = -1;
        mBaselineKernelMtu = 0;
        mIssuedLinkMtu = 0;
        mLastSafeResult = null;
        mRestorePending = false;
        mPendingObservedKernelMtu = 0;
    }

    static boolean isApplicable(String device, String operationMode, String operatorNumerics,
            int phoneId, boolean validSubId, boolean dedicatedImsApn, int transportWwan,
            int currentTransport) {
        return "m11q".equals(device) && "legacy".equals(operationMode)
                && hasSingleOperatorForPhone(operatorNumerics, phoneId) && validSubId
                && dedicatedImsApn && transportWwan == currentTransport;
    }

    static boolean isM11qLegacyDevice(String device, String operationMode) {
        return "m11q".equals(device) && "legacy".equals(operationMode);
    }

    /** Accept only one populated numeric in slots 0/1, attached to the matching phone slot. */
    static boolean hasSingleOperatorForPhone(String operatorNumerics, int phoneId) {
        if (operatorNumerics == null || (phoneId != 0 && phoneId != 1)) return false;
        String[] slots = operatorNumerics.split(",", -1);
        if (slots.length > 2) {
            for (int i = 2; i < slots.length; i++) {
                if (!slots[i].trim().isEmpty()) return false;
            }
        }
        int populated = 0;
        int populatedSlot = -1;
        for (int i = 0; i < Math.min(slots.length, 2); i++) {
            String value = slots[i].trim();
            if (value.isEmpty()) continue;
            populated++;
            populatedSlot = i;
            if (!isOperatorNumeric(value)) return false;
        }
        return populated == 1 && populatedSlot == phoneId;
    }

    private static boolean isOperatorNumeric(String value) {
        if (value.length() < 5 || value.length() > 6) return false;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) < '0' || value.charAt(i) > '9') return false;
        }
        return true;
    }

    private static boolean validV4(int value) {
        return value >= MIN_V4 && value <= MAX_MTU;
    }

    private static boolean validV6(int value) {
        return value >= MIN_V6 && value <= MAX_MTU;
    }

    private static boolean validKernel(int value) {
        return value >= MIN_V4 && value <= MAX_MTU;
    }
}

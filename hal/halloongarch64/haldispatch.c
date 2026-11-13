/*
 * PROJECT:     LiberNT LoongArch64 HAL
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF
 * PURPOSE:     The private HAL dispatch table
 *
 * The kernel imports this table as data and reaches the platform services that
 * are not part of the public HAL export set through HALPRIVATEDISPATCH
 * [haltypes.h]; the fallback kernel in ntos/fstub/haldispatch.c answers the
 * same calls when there is no HAL at all. Every entry below is a routine this
 * HAL already implements for the same service. An entry with no routine behind
 * it is left out of the initializer and is therefore NULL: the kernel either
 * has a fallback for it (ntos/fstub) or tests the pointer before use, so NULL
 * says "this platform has no such service" instead of a call that pretends to
 * answer.
 *
 * Two groups cannot be filled in here because they depend on state discovered
 * later: HalFlushIoRectangleExternalCache is installed by
 * HalpLa64InitializeCache once CPUCFG has reported the cache geometry, and the
 * three secondary-interrupt entries are installed by
 * HalpSecondaryInitializeDispatch once the controllers are mapped.
 */

#include <ntifs.h>
#include <ndk/halfuncs.h>
#include "halp.h"

/* nthalfuncs turns every name in this table into a HALPRIVATEDISPATCH access,
 * which cannot be a designator; the definitions below are what is being
 * defined here. */
#undef HalPciTranslateBusAddress
#undef HalPciAssignSlotResources
#undef HalHaltSystem
#undef KdGetPciDataByOffset
#undef HalGetInterruptVectorOverride
#undef HalGetProcessorId

/* The kernel's halt request carries no action: it means "stop the machine".
 * The one stop path this port has is HalReturnToFirmware, which records that
 * no reset protocol is reachable and parks the core on the idle instruction. */
static
VOID
NTAPI
HalpLa64HaltSystem(VOID)
{
    HalReturnToFirmware(HalHaltRoutine);
}

HAL_PRIVATE_DISPATCH HalPrivateDispatchTable =
{
    .Version = HAL_PRIVATE_DISPATCH_VERSION,

    /* The host bridge translates its own bus addresses and maps bus I/O ports
     * into the memory window; both directions come back as CPU physical
     * addresses. The legacy slot allocator is the one in stubs.c, which
     * reports STATUS_NOT_SUPPORTED: the PnP PCI driver allocates from the
     * resources the HAL publishes, not from a slot interface. */
    .HalPciTranslateBusAddress = HalTranslateBusAddress,
    .HalPciAssignSlotResources = HalAssignSlotResources,

    /* Stopping the machine. */
    .HalHaltSystem = HalpLa64HaltSystem,

    /* The debugger reads configuration space with the lock-free reader: at
     * the time it runs the other processors are frozen and may hold the host
     * bridge lock, so the ordinary path would deadlock. There is no
     * debugger-side writer, so KdSetPciDataByOffset stays NULL. */
    .KdGetPciDataByOffset = HalpKdReadPciConfig,

    /* Translation from the platform's source number to the vector the kernel
     * dispatches on, plus the IRQL and affinity of that vector. The reverse
     * query stays NULL: the controllers keep polarity per source for their own
     * programming and the platform publishes no vector-to-input interface. */
    .HalGetInterruptVectorOverride = HalGetInterruptVector,

    /* The CPUID of a processor by NT processor number, read from the core's
     * own CSR. */
    .HalGetProcessorId = HalGetProcessorIdByNtNumber,
};

/* EOF */

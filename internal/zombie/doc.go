// Package zombie removes orphan TC telemetry filters left over by a
// previous agent run that exited without unloading them.
//
// When the agent crashes mid-flight, its clsact filters stay
// attached to kernel interfaces and keep the previous BPF program
// alive via reference. If the new agent then attaches its own
// filters without first cleaning up, two outcomes are possible:
//
//   - On the same interface as before, the kernel re-uses the
//     filter slot and the old program is freed — harmless but not
//     guaranteed across implementations.
//   - On a different interface (config change, host re-plumbing),
//     the old filter never gets a replacement and the previous
//     program keeps running, double-counting bytes for the same
//     traffic and producing billing corruption.
//
// [Hunt] is called early in [agent.Bootstrap], before any new BPF
// program is loaded, so that the orphan's program reference is
// dropped before we install our own collection.
package zombie

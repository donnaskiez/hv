# HV - Experimental Hypervisor

A work-in-progress hypervisor for learning purposes, featuring a flexible VMX configuration system and comprehensive logging capabilities.

## Features

### VMX Configuration System
- Flexible configuration management for Virtual Machine Extensions (VMX)
- Customizable CPU features including preemption timer and unrestricted mode
- Advanced memory management with configurable stack sizes and huge page support
- Performance optimization options for TLB flush and caching
- Comprehensive debug options with CR/DR access monitoring
- Security features including NX, SMAP, and SMEP enforcement
- I/O control with configurable bitmap support

### Logging and Monitoring
- Multi-level logging system with configurable categories
- Performance monitoring capabilities
- Debug exception handling
- Preemption timer support with customizable intervals

### Current Limitations
- APIC virtualization is preliminary (only TPR shadowing)
- Unconditional I/O exiting needs stability improvements

## System Requirements
- Windows 10 22H2 (tested version)
- Intel CPU with VMX support

## Configuration Options

### CPU Features
- Preemption timer control
- Unrestricted mode support

### Memory Management
- Configurable host and guest stack sizes
- Huge pages support (optional)

### Performance Options
- TLB flush optimization
- Caching controls
- MSR bitmap optimization

### Debug Features
- Debug exception monitoring
- Invalid MSR access trapping
- CR access monitoring

### Security Features
- NX enforcement
- SMAP/SMEP support

## References

- [Intel Manual Volume 3](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [Hypervisor From Scratch](https://rayanfam.com/topics/hypervisor-from-scratch-part-1/)
- [Daax's 5 days to virtualization series](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/)
- [Felix Cloutiers x86 instruction reference](https://www.felixcloutier.com/x86/)
- [VMware paper on minimising hardware VM exits](https://www.usenix.org/system/files/conference/atc12/atc12-final158.pdf)
- [FreeBSD vmx.c](https://github.com/freebsd/freebsd-src/blob/c7ffe32b1b7de9d72add1b44d5d3a3a14605a8f0/sys/amd64/vmm/intel/vmx.c)
- [FreeBSD TPR shadowing patch](https://reviews.freebsd.org/D22942)
# hv

work in progress hypervisor for learning purposes but also hoping to build something around it in the future.

- apic virtualisation is very initial and only includes TPR shadowing. It technically works for a very short period but then the cpu hard faults. Ive tried to reference freebsd and linux but i cant seem to get it consistently working and the manual is fairly vague when it comes to TPR shadowing.
- unconditional io exiting is buggy and will crash u

## windows versions

ive only tested it on win10 22h2, so use are ur own risk

## Sources:

- [intel manual volume 3](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [Hypervisor From Scratch](https://rayanfam.com/topics/hypervisor-from-scratch-part-1/)
- [Daax's 5 days to virtualization series](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/)
- [Felix Cloutiers x86 instruction reference](https://www.felixcloutier.com/x86/)
- [vmware paper on minimising hardware vm exits](https://www.usenix.org/system/files/conference/atc12/atc12-final158.pdf)
- [FreeBSD vmx.c](https://github.com/freebsd/freebsd-src/blob/c7ffe32b1b7de9d72add1b44d5d3a3a14605a8f0/sys/amd64/vmm/intel/vmx.c)
- [FreeBSD TPR shadowing patch](https://reviews.freebsd.org/D22942)
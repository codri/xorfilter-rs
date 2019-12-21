# XorFilter

A Rust implementation of the XorFilter data structure defined here:

https://lemire.me/blog/2019/12/19/xor-filters-faster-and-smaller-than-bloom-filters/
https://arxiv.org/abs/1912.08258
https://github.com/FastFilter/xorfilter

## What it does

It allows you to check against a list of objects(hashes rather) with a low memory/CPU overhead.
The original paper describes it as a good alternative to Bloom Filters and variations of it(Cuckoo filter),
due to lower memory usage(8bit per item, for 1% false positives).

## The situation

Mostly a POC, and a mot a mot translation of the Go implementation.
It has a couple of tests. Not benchmarked/profiled yet.

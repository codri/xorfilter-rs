#[derive(Default)]
struct Xor8 {
    seed: u64,
    block_length: usize,
    fingerprints: Vec<u8>,
}

impl Xor8 {
    fn new(keys: &[u64]) -> Self {
        let size = keys.len();

        let mut capacity = 32 + (1.23 * size as f64).ceil() as usize;
        capacity = capacity / 3 * 3;

        let mut filter: Self = Default::default();
        filter.block_length = capacity / 3;
        filter.fingerprints = vec![0; capacity];

        let mut rng_counter = 1;
        filter.seed = splitmix64(&mut rng_counter);

        let mut q0: Vec<KeyIndex> = vec![Default::default(); filter.block_length];
        let mut q1: Vec<KeyIndex> = vec![Default::default(); filter.block_length];
        let mut q2: Vec<KeyIndex> = vec![Default::default(); filter.block_length];
        let mut stack: Vec<KeyIndex> = vec![Default::default(); size];

        let mut sets0: Vec<XorSet> = vec![Default::default(); filter.block_length];
        let mut sets1: Vec<XorSet> = vec![Default::default(); filter.block_length];
        let mut sets2: Vec<XorSet> = vec![Default::default(); filter.block_length];

        loop {
            for i in 0..size {
                let key = keys[i];
                let hs = filter.get_h0_h1_h2(key);
                sets0[hs.h0].xor_mask ^= hs.h;
                sets0[hs.h0].count += 1;
                sets1[hs.h1].xor_mask ^= hs.h;
                sets1[hs.h1].count += 1;
                sets2[hs.h2].xor_mask ^= hs.h;
                sets2[hs.h2].count += 1;
            }

            let mut q0_size = 0;
            let mut q1_size = 0;
            let mut q2_size = 0;

            for i in 0..filter.block_length {
                if sets0[i].count == 1 {
                    q0[q0_size].index = i;
                    q0[q0_size].hash = sets0[i].xor_mask;
                    q0_size += 1;
                }
                if sets1[i].count == 1 {
                    q1[q1_size].index = i;
                    q1[q1_size].hash = sets1[i].xor_mask;
                    q1_size += 1;
                }
                if sets2[i].count == 1 {
                    q2[q2_size].index = i;
                    q2[q2_size].hash = sets2[i].xor_mask;
                    q2_size += 1;
                }
            }

            let mut stack_size = 0;

            while q0_size + q1_size + q2_size > 0 {
                while q0_size > 0 {
                    q0_size -= 1;
                    let key_index = q0[q0_size];
                    let index = key_index.index;
                    if sets0[index].count == 0 {
                        continue;
                    }
                    let hash = key_index.hash;
                    let h1 = filter.get_h1(hash);
                    let h2 = filter.get_h2(hash);

                    stack[stack_size] = key_index;
                    stack_size += 1;

                    sets1[h1].xor_mask ^= hash;
                    sets1[h1].count -= 1;

                    if sets1[h1].count == 1 {
                        q1[q1_size].index = h1;
                        q1[q1_size].hash = sets1[h1].xor_mask;
                        q1_size += 1;
                    }

                    sets2[h2].xor_mask ^= hash;
                    sets2[h2].count -= 1;

                    if sets2[h2].count == 1 {
                        q2[q2_size].index = h2;
                        q2[q2_size].hash = sets2[h2].xor_mask;
                        q2_size += 1;
                    }
                }

                while q1_size > 0 {
                    q1_size -= 1;
                    let mut key_index = q1[q1_size];
                    let index = key_index.index;
                    if sets1[index].count == 0 {
                        continue;
                    }
                    let hash = key_index.hash;
                    let h0 = filter.get_h0(hash);
                    let h2 = filter.get_h2(hash);
                    key_index.index += filter.block_length;
                    stack[stack_size] = key_index;
                    stack_size += 1;
                    sets0[h0].xor_mask ^= hash;
                    sets0[h0].count -= 1;
                    if sets0[h0].count == 1 {
                        q0[q0_size].index = h0;
                        q0[q0_size].hash = sets0[h0].xor_mask;
                        q0_size += 1;
                    }

                    sets2[h2].xor_mask ^= hash;
                    sets2[h2].count -= 1;

                    if sets2[h2].count == 1 {
                        q2[q2_size].index = h2;
                        q2[q2_size].hash = sets2[h2].xor_mask;
                        q2_size += 1;
                    }
                }

                while q2_size > 0 {
                    q2_size -= 1;
                    let mut key_index = q2[q2_size];
                    let index = key_index.index;
                    if sets2[index].count == 0 {
                        continue;
                    }

                    let hash = key_index.hash;
                    let h0 = filter.get_h0(hash);
                    let h1 = filter.get_h1(hash);
                    key_index.index += 2 * filter.block_length;

                    stack[stack_size] = key_index;
                    stack_size += 1;
                    sets0[h0].xor_mask ^= hash;
                    sets0[h0].count -= 1;

                    if sets0[h0].count == 1 {
                        q0[q0_size].index = h0;
                        q0[q0_size].hash = sets0[h0].xor_mask;
                        q0_size += 1;
                    }
                    sets1[h1].xor_mask ^= hash;
                    sets1[h1].count -= 1;

                    if sets1[h1].count == 1 {
                        q1[q1_size].index = h1;
                        q1[q1_size].hash = sets1[h1].xor_mask;
                        q1_size += 1;
                    }
                }
            }

            if stack_size == size {
                break; // success
            }

            for i in 0..sets0.len() {
                sets0[i] = Default::default()
            }

            for i in 0..sets1.len() {
                sets1[i] = Default::default()
            }

            for i in 0..sets2.len() {
                sets2[i] = Default::default()
            }

            filter.seed = splitmix64(&mut rng_counter);
        }

        let mut stack_size = size;

        while stack_size > 0 {
            stack_size -= 1;
            let ki = stack[stack_size];
            let mut val = fingerprint(ki.hash) as u8;
            if ki.index < filter.block_length {
                val ^= filter.fingerprints[(filter.get_h1(ki.hash) + filter.block_length)]
                    ^ filter.fingerprints[(filter.get_h2(ki.hash) + 2 * filter.block_length)];
            } else if ki.index < 2 * filter.block_length {
                val ^= filter.fingerprints[filter.get_h0(ki.hash)]
                    ^ filter.fingerprints[(filter.get_h2(ki.hash) + 2 * filter.block_length)]
            } else {
                val ^= filter.fingerprints[filter.get_h0(ki.hash)]
                    ^ filter.fingerprints[(filter.get_h1(ki.hash) + filter.block_length)]
            }
            filter.fingerprints[ki.index] = val;
        }

        filter
    }

    fn contains(&self, key: u64) -> bool {
        let hash = mixsplit(key, self.seed);
        let f = fingerprint(hash) as u8;
        let r0 = hash as usize;
        let r1 = rotl64(hash, 21) as usize;
        let r2 = rotl64(hash, 42) as usize;
        let h0 = reduce(r0, self.block_length);
        let h1 = reduce(r1, self.block_length) + self.block_length;
        let h2 = reduce(r2, self.block_length) + 2 * self.block_length;
        f == (self.fingerprints[h0] ^ self.fingerprints[h1] ^ self.fingerprints[h2])
    }

    fn get_h0_h1_h2(&self, k: u64) -> Hashes {
        let hash = mixsplit(k, self.seed);
        Hashes {
            h: hash,
            h0: self.get_h0(hash),
            h1: self.get_h1(hash),
            h2: self.get_h2(hash),
        }
    }

    fn get_h0(&self, hash: u64) -> usize {
        reduce(hash as usize, self.block_length)
    }

    fn get_h1(&self, hash: u64) -> usize {
        reduce(rotl64(hash, 21) as usize, self.block_length)
    }

    fn get_h2(&self, hash: u64) -> usize {
        reduce(rotl64(hash, 42) as usize, self.block_length)
    }
}

#[derive(Copy, Clone, Default)]
struct XorSet {
    xor_mask: u64,
    count: usize,
}

struct Hashes {
    h: u64,
    h0: usize,
    h1: usize,
    h2: usize,
}

#[derive(Copy, Clone, Default)]
struct KeyIndex {
    hash: u64,
    index: usize,
}

fn murmur64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    h
}

const PRIME_1: u64 = 11_400_714_785_074_694_791;
const PRIME_2: u64 = 14_029_467_366_897_019_727;
const PRIME_3: u64 = 1_609_587_929_392_839_161;
const PRIME_4: u64 = 9_650_029_242_287_828_579;
const PRIME_5: u64 = 2_870_177_450_012_600_261;

fn xx_hash_64(mut v: u64, seed: u64) -> u64 {
    let mut hash = seed.wrapping_add(PRIME_5);
    let mut k1 = v.wrapping_mul(PRIME_2);
    k1 = k1.rotate_left(31);
    k1 = k1.wrapping_mul(PRIME_1);
    hash ^= k1;
    hash = hash.rotate_left(27);
    hash = hash.wrapping_mul(PRIME_1);
    hash = hash.wrapping_add(PRIME_4);
    hash
}

fn splitmix64(seed: &mut u64) -> u64 {
    *seed = (*seed).wrapping_add(0x9E3779B97F4A7C15);
    let mut z: u64 = seed.clone();
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn mixsplit(key: u64, seed: u64) -> u64 {
    // murmur64(key + seed)
    xx_hash_64(key, seed)
}

fn rotl64(n: u64, c: isize) -> u64 {
    (n << (c & 63)) | (n >> ((-c) & 63))
}

// 64 bit version of the modulo reduction
// https://github.com/lemire/fastrange/blob/master/fastrange.h#L39
fn reduce(hash: usize, n: usize) -> usize {
    // https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction//
    (((hash as u128) * (n as u128)) >> 64) as usize
}

fn fingerprint(hash: u64) -> u64 {
    hash ^ (hash >> 32)
}

#[test]
fn happy_path() {
    let xor = Xor8::new((0..10000).collect::<Vec<u64>>().as_ref());
    assert!(xor.contains(0));
    assert!(xor.contains(1));
    assert!(xor.contains(3));
    assert!(xor.contains(9999));
    assert!(!xor.contains(10000));
    assert!(!xor.contains(10001));
}

#[test]
fn split_mix_works_as_per_source() {
    assert_eq!(13679457532755275413, splitmix64(&mut 42));
}

#[test]
fn murmur64_works_as_per_source() {
    assert_eq!(9297814886316923340, murmur64(42));
}

#[test]
fn reduce_works_as_per_source() {
    assert_eq!(2, reduce(365355135, 101120121201));
}

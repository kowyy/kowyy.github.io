---
title: Parallelism
date: 2025-12-18
categories: [Optimization, Parallelism]
tags: [c++]     # TAG names should always be lowercase
description: 3D Ray Tracing Renderer sequential to parallelism.
---

# Sequential to Parallel Optimization with TBB

This is a comprehensive 3D ray tracing renderer implemented in C++ that demonstrates performance optimization through parallelization. The project showcases the evolution from sequential execution to parallel processing using Intel Threading Building Blocks (TBB), highlighting the performance gains achievable through proper parallel design patterns.

With this project I wanted to learn about threads, optimization and performance.

## Architecture

### Three Implementations

**1. AOS (Array of Structures): `aos/`**

Sequential implementation that serves as the baseline for performance comparison. This variant stores complete RGB pixels together in memory. It uses a single-threaded rendering loop and provides the reference point for benchmarking sequential performance.

**2. SOA (Structure of Arrays): `soa/`**

Sequential implementation with an alternative memory layout. Instead of storing RGB values together, this variant separates R, G, B channels into independent arrays. This organization provides better memory access patterns that could potentially benefit from vectorization, though the implementation remains sequential. It serves as a baseline for comparing different memory layouts.

**3. PAR (Parallel with TBB): `par/`**

Parallel implementation using Intel TBB, which demonstrates multiple parallelization strategies. The implementation supports three partitioner types: `auto_partitioner` for dynamic load balancing, `static_partitioner` for fixed work distribution, and `simple_partitioner` for basic subdivision. You can configure several threading parameters including the number of threads (to control hardware concurrency), grain size (which determines work chunk granularity), and partitioner selection.

### Common library (`common/`)

All three implementations share these fundamental building blocks:

1. Vector Math (`vector.hpp/cpp`) - 3D vector operations
2. Ray (`ray.hpp/cpp`) - Ray representation and manipulation
3. Materials (`material.hpp/cpp`) - Surface properties and interactions
4. Objects (`object.hpp/cpp`) - Geometric primitives
5. Scene (`scene.hpp/cpp`) - Object and material management
6. Camera (`camera.hpp/cpp`) - View and ray generation
7. Color (`color.hpp/cpp`) - RGB handling with gamma correction

## Parallel Implementation

### Thread-Local Random Number Generators

```cpp
struct RenderJob {
    // Thread-safe RNG initialization
    tbb::enumerable_thread_specific<std::mt19937_64> ray_rngs;
    tbb::enumerable_thread_specific<std::mt19937_64> material_rngs;
    
    void init_rngs() {
        // Pre-generated seeds for reproducibility
        std::vector<std::uint64_t> ray_seeds;
        std::vector<std::uint64_t> material_seeds;
        
        ray_rngs = tbb::enumerable_thread_specific<std::mt19937_64>([this] {
            static std::atomic<size_t> counter{0};
            size_t idx = counter++ % this->ray_seeds.size();
            return std::mt19937_64{this->ray_seeds[idx]};
        });
    }
};
```

The key insight here is that each thread gets its own RNG instance, which avoids synchronization overhead while still maintaining deterministic results through pre-seeded generators. This is particularly important in ray tracing where you need lots of random numbers but also want reproducible results.

### Parallel Rendering Task

```cpp
class RenderTask {
    void operator()(tbb::blocked_range<int> const& r) const {
        // Access thread-local RNGs without locks
        ThreadLocalRNGs local_rngs{
            &job->ray_rngs.local(), 
            &job->material_rngs.local()
        };
        
        // Process assigned scanlines
        for (int j = r.begin(); j != r.end(); ++j) {
            for (int i = 0; i < image_width; ++i) {
                // Render pixel with thread-local state
                render_pixel(i, j, local_rngs);
            }
        }
    }
};
```

The task functor operates on a range of scanlines, with each thread processing complete rows. This maintains cache locality since pixels in the same row tend to access similar scene data.

#### Configurable Parallelism

```cpp
void render_loop(RenderJob& job) {
    // Optional thread count limitation
    std::unique_ptr<tbb::global_control> global_limit;
    if (job.cfg.get_num_threads() > 0) {
        global_limit = std::make_unique<tbb::global_control>(
            tbb::global_control::max_allowed_parallelism,
            static_cast<size_t>(job.cfg.get_num_threads())
        );
    }
    
    // Configurable grain size and partitioner
    int grain = job.cfg.get_grain_size();
    tbb::blocked_range<int> range(0, height, static_cast<size_t>(grain));
    
    std::string partitioner = job.cfg.get_partitioner();
    if (partitioner == "static") {
        tbb::parallel_for(range, task, tbb::static_partitioner());
    } else if (partitioner == "simple") {
        tbb::parallel_for(range, task, tbb::simple_partitioner());
    } else {
        tbb::parallel_for(range, task, tbb::auto_partitioner());
    }
}
```

Runtime configuration allows you to experiment with different parallelization strategies without needing to recompile. This is really useful for testing the application.

### Configuration System

The parallel implementation extends the configuration format with TBB-specific parameters:

```
# Traditional parameters
image_width: 1920
samples_per_pixel: 20
max_depth: 5

# TBB-specific parameters
num_threads: 16        # -1 for automatic (all cores)
grain_size: 50         # Rows per task chunk
partitioner: auto      # auto, static, or simple
```

Configuration options explained:

num_threads: Setting this to -1 uses automatic detection (all hardware threads). Values greater than 0 allow you to specify an exact thread count, which is useful for controlled experiments.

grain_size: Smaller values give you better load balancing but come with higher overhead. Larger values reduce overhead but might cause load imbalance.

partitioner: The `auto` option uses TBB's adaptive load balancing and is generally recommended. The `static` partitioner provides fixed equal distribution, which is predictable but less flexible. The `simple` partitioner offers basic recursive subdivision with minimal overhead.

## Ray Tracing Algorithm

The core rendering algorithm remains the same across all implementations:

```cpp
color ray_color(ray const& r, scene const& scn, int depth, RNG& rng) {
    if (depth <= 0) return color{0,0,0};
    
    if (scn.hit(r, t_min, t_max, rec)) {
        if (rec.mat_ptr->scatter(r, rec, scattered, rng)) {
            return attenuation * ray_color(scattered, scn, depth-1, rng);
        }
        return color{0,0,0};
    }
    
    // Background gradient
    return lerp(background_light, background_dark, t);
}
```

### Rendering Pipeline

The rendering process follows these stages:

For each pixel (i, j), which gets parallelized in the PAR implementation, the renderer generates `samples_per_pixel` rays with random jitter. Each ray gets cast through the scene, and the algorithm recursively traces bounces up to `max_depth`. Finally, it accumulates and averages the colors.

Ray-object intersection happens sequentially per ray. The algorithm tests the ray against all objects in the scene and finds the closest hit within the range [t_min, t_max].

Material scattering also happens sequentially per ray. Matte materials produce random diffuse directions, metal materials reflect with optional diffusion, and refractive materials either refract or reflect based on Snell's law.

The output stage uses thread-safe writes in the PAR implementation. The renderer applies gamma correction, converts to 8-bit RGB, and performs direct writes to the image buffer without needing any synchronization.

## Performance Evaluation

### Metrics

Using `perf stat`, the analysis captures several important metrics. Execution time measures wall-clock duration, while CPU cycles counts total processor cycles used. Instructions tracks the total instructions executed. Energy consumption gets measured through `power/energy-pkg/` for CPU package energy and `power/energy-ram/` for DRAM energy. IPC (Instructions Per Cycle) gets computed from the instructions/cycles ratio.

### Expected Results

Sequential implementations (AOS/SOA) provide baseline execution time with single-core utilization and lower total energy, though they have higher energy per unit time.

Parallel implementations (PAR) should show near-linear speedup up to the thread count, with multi-core utilization. Total energy consumption is higher, but energy per frame drops significantly. Efficiency varies depending on the partitioner and grain size you choose.

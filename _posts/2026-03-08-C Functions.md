---
title: OS System Calls - mycalc & mydu
date: 2025-10-05
categories: [Operating Systems]
tags: [c, linux, posix]
description: Implementing a calculator and disk usage utility using only POSIX system calls. Simple project, but found it curious to replicate functions which I use everyday without using default libraries.
---
# Low-Level POSIX Programming: mycalc and mydu

[Repositorio](https://github.com/100525023/ssoo_p1)

## Overview

This project implements two command-line utilities using only low-level POSIX system calls, with no standard C library functions for I/O or string manipulation. The goal is to interact directly with the kernel, understanding what really happens between a C program and the operating system.

The strict constraint of excluding `stdio.h` forces you to rethink everything you take for granted. No `printf`, no `scanf`, no `strlen`. Every operation has to be built from scratch or done through raw file descriptors.

### Program Breakdown

- **mycalc.c**: A basic integer calculator with logging and history retrieval
- **mydu.c**: A recursive disk usage utility that persists results to a binary file

## mycalc: A Calculator Without stdio

The calculator has two modes: **Interactive** (perform an arithmetic operation) and **History** (retrieve a past operation from the log by line number).

### Custom String Utilities

Since `string.h` and `stdio.h` are off the table, the first thing to build is a small set of helper functions to replace what the standard library would normally handle silently.

```c
/* counts how long a string is, since we can't use strlen */
int my_strlen(const char *str) {
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}
```

Simple enough, but it compounds quickly. Every `write` call needs a length, so `my_strlen` gets called constantly throughout the program.

The more interesting ones are `my_atoi` and `my_itoa`. Parsing a string into an integer is straightforward, but converting an integer back into a printable string is trickier than it looks:

```c
void my_itoa(int val, char *buf) {
    int          i = 0;
    unsigned int uval;

    if (val < 0) {
        buf[i++] = '-';
        uval = (unsigned int)(-val);
    } else {
        uval = (unsigned int)val;
    }

    int start = i;
    do {
        buf[i++] = (char)((uval % 10) + '0');
        uval /= 10;
    } while (uval);

    buf[i] = '\0';

    int end = i - 1;
    while (start < end) {
        char tmp   = buf[start];
        buf[start] = buf[end];
        buf[end]   = tmp;
        start++;
        end--;
    }
}
```

The key issue: extracting digits with `% 10` gives you the least significant digit first. So you build the string in reverse, then flip it. The `start` index skips the `-` sign if there is one, so the reversal only touches the digit portion.

### Input Validation

Before any arithmetic, every input gets validated. A valid number is either all digits or a `-` followed by all digits:

```c
int is_valid_number(const char *str) {
    if (str == (void *)0 || *str == '\0') return 0;
    if (*str == '-') str++;
    return is_all_digits(str);
}
```

A lone `-` with nothing after it, an empty string, or any string containing letters all return 0. The operator is validated separately — it must be exactly one character and one of `+`, `-`, `x`, `/`.

Division by zero is caught explicitly before the operation runs:

```c
else if (op == '/') {
    if (num2 == 0) {
        print_stderr("Error: Division by zero\n");
        return -1;
    }
    result = num1 / num2;
}
```

### Logging with System Calls

Every successful operation gets appended to `mycalc.log`. The output line is built once into a buffer and then reused for both stdout and the log file — no redundant formatting:

```c
char output_buffer[MAX_OUTPUT_LEN];
concat_output(output_buffer, num1_str, op_str, num2_str, res_str);

print_stdout(output_buffer);

int fd = open(log_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
if (fd == -1) {
    print_stderr("Error: Could not open log file\n");
    return -1;
}

ssize_t to_write = (ssize_t)my_strlen(output_buffer);
if (write(fd, output_buffer, (size_t)to_write) != to_write) {
    print_stderr("Error: Could not write to log file\n");
    close(fd);
    return -1;
}

close(fd);
```

`O_WRONLY | O_CREAT | O_APPEND` does exactly what it says: open for writing, create the file if it doesn't exist, and never overwrite existing content. The `0644` mode means the owner can read and write, everyone else can only read.

Notice the write verification — we check that `write` actually wrote the number of bytes we asked for. On a full disk or a broken pipe, `write` can return a short count instead of failing outright. Most beginners skip this check.

### History Mode: Byte-by-Byte Line Seeking

The `-b` flag takes a line number and prints that entry from the log. Since there's no `fgets` or line-oriented reading, the implementation walks through the file one byte at a time, counting newlines:

```c
while (read(fd, buf, 1) == 1) {
    if (current_line == target_line) {
        if (out_len >= MAX_OUTPUT_LEN) {
            print_stderr("Error: Log line too long\n");
            close(fd);
            return -1;
        }
        line_found         = 1;
        out_buf[out_len++] = buf[0];
        if (buf[0] == '\n') break;
    } else {
        if (buf[0] == '\n') current_line++;
    }
}
```

When we're on the wrong line, we just count newlines and move on. When we reach the target, we start copying bytes into `out_buf` until we hit a newline or run out of space. If the target line never appears, `line_found` stays 0 and we report an error.

## mydu: Recursive Disk Usage

`mydu` replicates the behavior of the standard `du` command: walk a directory tree recursively, printing the cumulative size of each directory in kilobytes. It also persists every result to a binary file for history viewing.

### Recursive Traversal

The core of the program is `calculate_directory_size`, which calls itself recursively on every subdirectory it finds:

```c
long calculate_directory_size(const char *current_path, int bin_fd) {
    DIR           *dir;
    struct dirent *entry;
    struct stat    statbuf;
    long           total_size = 0;
    char           next_path[4096];

    if (lstat(current_path, &statbuf) == -1) {
        fprintf(stderr, "Error: cannot stat '%s'\n", current_path);
        return 0;
    }

    total_size += statbuf.st_blocks / 2;

    dir = opendir(current_path);
    if (!dir) {
        fprintf(stderr, "Error: cannot open directory '%s'\n", current_path);
        return total_size;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        // ...
    }
```

Two things to pay attention to here. First, `lstat` is used instead of `stat`. The difference matters: `stat` follows symlinks, `lstat` doesn't. If a symlink points to a directory, `stat` would recurse into it (potentially forever), while `lstat` correctly treats it as a file with its own size.

Second, `.` and `..` are always present in every directory listing. Forgetting to skip them causes infinite recursion.

### Disk Size Calculation

```c
total_size += statbuf.st_blocks / 2;
```

`st_blocks` is measured in 512-byte units by POSIX. Dividing by 2 converts to kilobytes. This is how the real `du` does it — it counts allocated blocks, not the logical file size. That's why `du` sometimes reports a larger number than you'd expect from the file sizes alone: sparse files, filesystem metadata, and block alignment all play a role.

Subdirectory sizes bubble up through the recursion:

```c
if (S_ISDIR(statbuf.st_mode)) {
    total_size += calculate_directory_size(next_path, bin_fd);
} else {
    total_size += statbuf.st_blocks / 2;
}
```

The output happens after the recursion returns, so subdirectories are always printed before their parent — exactly like the real `du`.

### Binary Persistence

Results are stored in a binary file using a fixed-size struct:

```c
typedef struct {
    long size;
    char path[4096];
} DirHistoryRecord;
```

Writing is done with the `write` system call directly on the struct:

```c
if (bin_fd != -1) {
    DirHistoryRecord rec;
    rec.size = total_size;
    strncpy(rec.path, current_path, sizeof(rec.path) - 1);
    rec.path[sizeof(rec.path) - 1] = '\0';

    if (write(bin_fd, &rec, sizeof(rec)) != (ssize_t)sizeof(rec)) {
        fprintf(stderr, "Error: failed to write record to binary file\n");
    }
}
```

Reading it back is symmetric — just `read` fixed-size chunks and print them:

```c
while ((bytes_read = read(fd, &rec, sizeof(DirHistoryRecord))) > 0) {
    if (bytes_read == (ssize_t)sizeof(DirHistoryRecord)) {
        printf("%ld\t%s\n", rec.size, rec.path);
    } else {
        fprintf(stderr, "Error: corrupt record in binary file\n");
        close(fd);
        return -1;
    }
}
```

A partial read means the file is corrupt — something wrote less than a full record. This is caught explicitly. The binary file is opened with `O_APPEND` so previous scan results are never overwritten, just accumulated.

### Path Safety

Building paths by string concatenation is one of the most common sources of buffer overflows in C. Every path construction goes through `snprintf` with an explicit size limit:

```c
int written = snprintf(next_path, sizeof(next_path),
                       "%s/%s", current_path, entry->d_name);
if (written < 0 || (size_t)written >= sizeof(next_path)) {
    fprintf(stderr, "Error: path too long, skipping '%s/%s'\n",
            current_path, entry->d_name);
    continue;
}
```

If the constructed path would exceed 4096 bytes, we skip the entry and keep going instead of silently truncating it into a wrong path.

## Execution

Compile both programs with:

```bash
gcc -Wall -Wextra -o mycalc mycalc.c
gcc -Wall -Wextra -o mydu mydu.c
```

Then run them:

```bash
# Calculator
./mycalc 5 + 10
./mycalc -5 x 3
./mycalc -b 1

# Disk usage
./mydu .
./mydu /home
./mydu -b
```

The `-Wall -Wextra` flags are worth keeping during development. Any unused variable or implicit conversion is a warning, and warnings in low-level C code usually point to something real.

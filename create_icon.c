// create_icon.c — writes the 32x32 icon for baby_screen_lock.
//
// A monitor with a padlock across the lower half. The picture is the screen
// lock: the glass is the display, the gold body is the lock a toddler cannot
// open. One file, no CRT, no external header. Every type and import is
// declared here. Build produces out\create_icon.exe. Running it writes
// out\app_icon.ico. --self-test also writes out\create_icon_self_test.txt
// and fuzzes the pixel helpers before that.
//
// The pixel buffer is a static array. Nothing is allocated and nothing is
// freed. The process exits when the file has been written.

typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef unsigned long long size_t;

#define NULL 0
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define GENERIC_WRITE 0x40000000
#define CREATE_ALWAYS 2
#define FILE_ATTRIBUTE_NORMAL 0x80
#define STD_OUTPUT_HANDLE ((DWORD)-11)

extern HANDLE CreateFileA(const char *name, DWORD access, DWORD share,
                                    void *sec, DWORD disp, DWORD flags, HANDLE templ);
extern BOOL WriteFile(HANDLE h, const void *buf, DWORD n, DWORD *wrote, void *ov);
extern BOOL CloseHandle(HANDLE h);
extern HANDLE GetStdHandle(DWORD kind);
extern void ExitProcess(DWORD code);
extern BOOL CreateDirectoryA(const char *name, void *sec);
extern char *GetCommandLineA(void);

// Fills size bytes at dst with the low 8 bits of val. The compiler emits calls
// to this. There is no CRT in this link. Returns dst.
void *memset(void *dst, int val, size_t size) {
    unsigned char *d = (unsigned char *)dst;
    while (size--) *d++ = (unsigned char)val;
    return dst;
}

// Copies size bytes from src to dst. The compiler emits calls to this. Returns
// dst.
void *memcpy(void *dst, const void *src, size_t size) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (size--) *d++ = *s++;
    return dst;
}

#define W 32
#define H 32

// One pixel in the icon, stored in the order the ICO XOR bitmap wants
// except that this struct keeps a separate alpha instead of packing BGRA yet.
// b, g, r are the color. a is 0 for the clear background and 255 for ink.
typedef struct Pixel {
    unsigned char b; // Blue. The ICO XOR bitmap stores this byte first.
    unsigned char g; // Green.
    unsigned char r; // Red.
    unsigned char a; // Alpha. 0 is the clear background. 255 is ink.
} Pixel;

// The whole icon. Cleared to alpha 0, then the drawing writes the monitor
// and the lock. Static storage, so it lasts until the process exits.
static Pixel px[H][W];

// Colors. The bezel and the stand are dark blue. The glass is a light blue.
// The lock body is gold, its bottom edge a deeper gold, the shackle silver,
// the keyhole dark, and the highlight a pale gold.
#define BEZEL_R 36
#define BEZEL_G 64
#define BEZEL_B 96
#define GLASS_R 126
#define GLASS_G 198
#define GLASS_B 232
#define LOCK_R 242
#define LOCK_G 176
#define LOCK_B 46
#define SHADE_R 196
#define SHADE_G 128
#define SHADE_B 28
#define SHACK_R 236
#define SHACK_G 240
#define SHACK_B 246
#define HOLE_R 42
#define HOLE_G 52
#define HOLE_B 68
#define HILITE_R 255
#define HILITE_G 244
#define HILITE_B 214

// How far commit_stack_pages walks, and how many bytes each step touches.
// 180 * 2500 stays inside the default 1 MiB stack reserve.
#define STACK_PROBE_CHUNK 2500
#define STACK_PROBE_STEPS 180

// Fixed generator for the fuzz. The same seed fails the same way twice.
static unsigned g_rng = 0xA11CEu;

// Next pseudo-random value.
static unsigned rnd(void) {
    g_rng = g_rng * 1664525u + 1013904223u;
    return g_rng;
}

// Write s to the console. Used for the one status line and for errors.
static void say(const char *s) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD wrote;
    while (s[n]) n++;
    if (h && h != INVALID_HANDLE_VALUE) WriteFile(h, s, n, &wrote, NULL);
}

// Commit each stack page by touching it, then the next frame further down.
// There is no __chkstk in this link. The pages stay committed afterwards.
static void commit_stack_pages(int stepsLeft) {
    volatile unsigned char page[STACK_PROBE_CHUNK];
    page[0] = (unsigned char)stepsLeft;
    if (stepsLeft > 1) commit_stack_pages(stepsLeft - 1);
    page[STACK_PROBE_CHUNK - 1] = page[0];
}

// TRUE when the command line contains --self-test as a substring.
static int wants_self_test(void) {
    const char *cmd = GetCommandLineA();
    const char *needle = "--self-test";
    if (!cmd) return 0;
    for (const char *p = cmd; *p; p++) {
        int i = 0;
        while (needle[i] && p[i] == needle[i]) i++;
        if (needle[i] == 0) return 1;
    }
    return 0;
}

// Paint one pixel if it sits inside the 32x32 buffer. Coordinates outside
// the buffer are ignored, which is what lets the fuzz throw random values
// at this function without a separate bounds check at every caller.
static void put(int x, int y, unsigned char r, unsigned char g, unsigned char b, unsigned char a) {
    if (x >= 0 && x < W && y >= 0 && y < H) {
        px[y][x].r = r;
        px[y][x].g = g;
        px[y][x].b = b;
        px[y][x].a = a;
    }
}

// Fill a width-by-height rectangle whose top-left is (x0, y0).
// put clips each pixel, so a rectangle that hangs off the icon is safe.
static void fill_rect(int x0, int y0, int w, int h, unsigned char r, unsigned char g, unsigned char b) {
    int x, y;
    for (y = y0; y < y0 + h; y++)
        for (x = x0; x < x0 + w; x++)
            put(x, y, r, g, b, 255);
}

// Fill the disk of the given radius centered at (cx, cy), inclusive of the
// radius (the compare is distance squared <= radius squared).
static void fill_circle(int cx, int cy, int radius, unsigned char r, unsigned char g, unsigned char b) {
    int x, y;
    for (y = cy - radius; y <= cy + radius; y++)
        for (x = cx - radius; x <= cx + radius; x++)
            if ((x - cx) * (x - cx) + (y - cy) * (y - cy) <= radius * radius)
                put(x, y, r, g, b, 255);
}

// Monitor with a padlock across the lower half of the glass.
// The bezel and the stand are drawn first. The shackle sits on the glass,
// and the lock body covers the bottom of the shackle and the stand's neck.
// Pixels this function does not touch stay whatever they were. The caller
// clears the buffer first so the background stays transparent.
static void draw_lock_icon(void) {
    // Dark bezel. The glass is inset so a frame stays visible on every side.
    fill_rect(3, 2, 26, 16, BEZEL_R, BEZEL_G, BEZEL_B);
    fill_rect(5, 4, 22, 12, GLASS_R, GLASS_G, GLASS_B);

    // Neck under the glass, then a wider foot. The lock covers the neck.
    fill_rect(14, 18, 4, 3, BEZEL_R, BEZEL_G, BEZEL_B);
    fill_rect(8, 23, 16, 2, BEZEL_R, BEZEL_G, BEZEL_B);

    // Shackle on the glass: two legs and a top bar. The opening is glass.
    fill_rect(12, 7, 2, 8, SHACK_R, SHACK_G, SHACK_B);
    fill_rect(18, 7, 2, 8, SHACK_R, SHACK_G, SHACK_B);
    fill_rect(12, 6, 8, 2, SHACK_R, SHACK_G, SHACK_B);

    // Gold body over the lower glass. The bottom edge is a darker band.
    fill_rect(10, 12, 12, 11, LOCK_R, LOCK_G, LOCK_B);
    fill_rect(10, 21, 12, 2, SHADE_R, SHADE_G, SHADE_B);

    // Keyhole: a small disk, then a one-pixel stem down the middle.
    fill_circle(16, 15, 1, HOLE_R, HOLE_G, HOLE_B);
    fill_rect(16, 17, 1, 2, HOLE_R, HOLE_G, HOLE_B);

    // Two-pixel highlight on the upper left of the body.
    put(11, 13, HILITE_R, HILITE_G, HILITE_B, 255);
    put(12, 13, HILITE_R, HILITE_G, HILITE_B, 255);
}

// TRUE when (x, y) is opaque and has this exact color.
static int pixel_is(int x, int y, unsigned char r, unsigned char g, unsigned char b) {
    return px[y][x].r == r && px[y][x].g == g && px[y][x].b == b && px[y][x].a == 255;
}

// TRUE when (x, y) was left transparent.
static int pixel_clear(int x, int y) {
    return px[y][x].a == 0;
}

// The AND-mask bit for pixel x. A 1 means transparent. Bit 7 of the byte
// is pixel 0 of that group of 8, which is the ICO convention.
static int mask_bit_set(int x, int y) {
    unsigned char row = 0;
    int i;
    // Rebuild the one byte that contains x. y selects the row.
    for (i = (x & ~7); i < (x & ~7) + 8 && i < W; i++) {
        if (px[y][i].a == 0)
            row = (unsigned char)(row | (unsigned char)(0x80 >> (i % 8)));
    }
    return (row & (unsigned char)(0x80 >> (x % 8))) != 0;
}

// The anchors the icon must keep: clear corners, glass, the hole through
// the shackle, the bezel, the shackle, the body, the shade, the keyhole,
// the highlight, and the stand foot.
// Returns 1 when every anchor holds, or 0 when one does not.
static int anchors_ok(void) {
    if (!pixel_clear(0, 0) || !pixel_clear(31, 0) || !pixel_clear(31, 31)) return 0;
    if (!pixel_is(8, 8, GLASS_R, GLASS_G, GLASS_B)) return 0;
    if (!pixel_is(15, 9, GLASS_R, GLASS_G, GLASS_B)) return 0;
    if (!pixel_is(3, 2, BEZEL_R, BEZEL_G, BEZEL_B)) return 0;
    if (!pixel_is(8, 23, BEZEL_R, BEZEL_G, BEZEL_B)) return 0;
    if (!pixel_is(14, 6, SHACK_R, SHACK_G, SHACK_B)) return 0;
    if (!pixel_is(12, 19, LOCK_R, LOCK_G, LOCK_B)) return 0;
    if (!pixel_is(12, 21, SHADE_R, SHADE_G, SHADE_B)) return 0;
    if (!pixel_is(16, 15, HOLE_R, HOLE_G, HOLE_B)) return 0;
    if (!pixel_is(11, 13, HILITE_R, HILITE_G, HILITE_B)) return 0;
    return 1;
}

// Clear the buffer, draw the icon, and check anchors plus the AND mask.
// A clear pixel's mask bit is 1. An opaque pixel's mask bit is 0.
static int draw_and_check(void) {
    int x, y;
    for (y = 0; y < H; y++) {
        for (x = 0; x < W; x++) {
            px[y][x].r = 0;
            px[y][x].g = 0;
            px[y][x].b = 0;
            px[y][x].a = 0;
        }
    }
    draw_lock_icon();
    if (!anchors_ok()) return 0;
    for (y = 0; y < H; y++) {
        for (x = 0; x < W; x++) {
            int bit = mask_bit_set(x, y);
            if (px[y][x].a == 0 && !bit) return 0;
            if (px[y][x].a == 255 && bit) return 0;
        }
    }
    return 1;
}

// Throw random coordinates and colors at put, fill_rect, and fill_circle,
// including values outside the bitmap. Then redraw the real icon and require
// the anchors again. iters is how many random operations to run.
// Returns 1 on success. A broken helper returns 0.
static int fuzz_pixels(int iters) {
    int i;
    Pixel saved;
    // An in-bounds pixel must survive puts that land outside the buffer.
    saved = px[1][1];
    put(-1, -1, 1, 2, 3, 255);
    put(W, H, 1, 2, 3, 255);
    put(1000, -1000, 9, 9, 9, 255);
    if (px[1][1].r != saved.r || px[1][1].g != saved.g ||
        px[1][1].b != saved.b || px[1][1].a != saved.a) return 0;

    for (i = 0; i < iters; i++) {
        int kind = (int)(rnd() % 3);
        int x = (int)(rnd() % 50) - 8;
        int y = (int)(rnd() % 50) - 8;
        unsigned char r = (unsigned char)(rnd() & 255);
        unsigned char g = (unsigned char)(rnd() & 255);
        unsigned char b = (unsigned char)(rnd() & 255);
        if (kind == 0) put(x, y, r, g, b, (unsigned char)(rnd() & 255));
        else if (kind == 1) fill_rect(x, y, (int)(rnd() % 40), (int)(rnd() % 40), r, g, b);
        else fill_circle(x, y, (int)(rnd() % 20), r, g, b);
    }
    // The random paint is thrown away. The icon itself has to come back.
    if (!draw_and_check()) return 0;
    return 1;
}

// Append one little-endian u16 to the file.
static void write_u16(HANDLE h, unsigned short v) {
    unsigned char b[2];
    DWORD wrote;
    b[0] = (unsigned char)(v & 0xFF);
    b[1] = (unsigned char)((v >> 8) & 0xFF);
    WriteFile(h, b, 2, &wrote, NULL);
}

// Append one little-endian u32 to the file.
static void write_u32(HANDLE h, unsigned int v) {
    unsigned char b[4];
    DWORD wrote;
    b[0] = (unsigned char)(v & 0xFF);
    b[1] = (unsigned char)((v >> 8) & 0xFF);
    b[2] = (unsigned char)((v >> 16) & 0xFF);
    b[3] = (unsigned char)((v >> 24) & 0xFF);
    WriteFile(h, b, 4, &wrote, NULL);
}

// Append one byte to the file.
static void write_byte(HANDLE h, unsigned char v) {
    DWORD wrote;
    WriteFile(h, &v, 1, &wrote, NULL);
}

// Write out\create_icon_self_test.txt. The drawing has already been checked.
static void write_self_test_log(void) {
    HANDLE h;
    const char *msg = "create_icon --self-test\r\nALL TESTS PASSED\r\n";
    DWORD n = 0;
    DWORD wrote;
    while (msg[n]) n++;
    h = CreateFileA("out\\create_icon_self_test.txt", GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        say("Error: cannot write self-test log\n");
        ExitProcess(1);
    }
    WriteFile(h, msg, n, &wrote, NULL);
    CloseHandle(h);
}

// Write the ICO. The pixel buffer must already be the finished icon.
// The XOR bitmap is bottom-up BGRA. The AND mask is bottom-up, 1 bit per
// pixel, with 1 meaning transparent so a viewer does not paint the clear
// corners black.
static void write_ico(void) {
    HANDLE f;
    int x, y;
    unsigned int image_size;
    unsigned int and_row_bytes = ((W + 31) / 32) * 4;
    unsigned int and_size = and_row_bytes * H;
    unsigned int xor_size = W * H * 4;

    image_size = 40 + xor_size + and_size;
    f = CreateFileA("out\\app_icon.ico", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        say("Error: cannot create out\\app_icon.ico\n");
        ExitProcess(1);
    }

    // ICO header: reserved, type = icon, one image.
    write_u16(f, 0);
    write_u16(f, 1);
    write_u16(f, 1);

    // Directory entry. The image bytes start at offset 22.
    write_byte(f, W);
    write_byte(f, H);
    write_byte(f, 0);
    write_byte(f, 0);
    write_u16(f, 1);
    write_u16(f, 32);
    write_u32(f, image_size);
    write_u32(f, 22);

    // BITMAPINFOHEADER. Height is doubled because the XOR and AND masks
    // are stored as one DIB.
    write_u32(f, 40);
    write_u32(f, W);
    write_u32(f, H * 2);
    write_u16(f, 1);
    write_u16(f, 32);
    write_u32(f, 0);
    write_u32(f, xor_size + and_size);
    write_u32(f, 0);
    write_u32(f, 0);
    write_u32(f, 0);
    write_u32(f, 0);

    // XOR pixels, bottom row first, bytes in BGRA order.
    for (y = H - 1; y >= 0; y--) {
        for (x = 0; x < W; x++) {
            write_byte(f, px[y][x].b);
            write_byte(f, px[y][x].g);
            write_byte(f, px[y][x].r);
            write_byte(f, px[y][x].a);
        }
    }

    // AND mask, bottom row first. Each row is padded to a multiple of 4 bytes.
    for (y = H - 1; y >= 0; y--) {
        unsigned char row[4];
        int i;
        for (i = 0; i < 4; i++) row[i] = 0;
        for (x = 0; x < W; x++) {
            if (px[y][x].a == 0)
                row[x / 8] = (unsigned char)(row[x / 8] | (unsigned char)(0x80 >> (x % 8)));
        }
        for (i = 0; i < 4; i++) write_byte(f, row[i]);
    }

    CloseHandle(f);
}

// Process entry. Commits the stack, creates the out directory, fuzzes the pixel
// helpers, and writes out\app_icon.ico. --self-test uses more fuzz iterations
// and also writes out\create_icon_self_test.txt. A failed anchor check exits
// with code 1.
void mainCRTStartup(void) {
    int selfTest = wants_self_test();
    int iters = selfTest ? 4000 : 400;

    // Commit the stack before the fuzz frames and the ICO locals run.
    commit_stack_pages(STACK_PROBE_STEPS);

    // out\ may not exist when this exe is launched by hand.
    CreateDirectoryA("out", NULL);

    if (!fuzz_pixels(iters)) {
        say("Error: icon pixels are not the screen-lock drawing\n");
        ExitProcess(1);
    }
    if (selfTest) write_self_test_log();

    write_ico();
    say("Created out\\app_icon.ico (32x32, 32-bit)\n");
    ExitProcess(0);
}

#!/usr/bin/env node
import { writeFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import zlib from 'node:zlib'

// PNG helpers (RGBA)
function crc32(buf) {
  let c = ~0 >>> 0
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i]
    for (let k = 0; k < 8; k++) {
      const mask = -(c & 1)
      c = (c >>> 1) ^ (0xEDB88320 & mask)
    }
  }
  return (~c) >>> 0
}

function writeChunk(type, data) {
  const len = Buffer.alloc(4)
  len.writeUInt32BE(data.length, 0)
  const typeBuf = Buffer.from(type, 'ascii')
  const crcBuf = Buffer.alloc(4)
  const crc = crc32(Buffer.concat([typeBuf, data]))
  crcBuf.writeUInt32BE(crc, 0)
  return Buffer.concat([len, typeBuf, data, crcBuf])
}

function encodePNG(width, height, rgba) {
  const signature = Buffer.from([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A])
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(width, 0)
  ihdr.writeUInt32BE(height, 4)
  ihdr.writeUInt8(8, 8)    // bit depth
  ihdr.writeUInt8(6, 9)    // color type: truecolor + alpha (RGBA)
  ihdr.writeUInt8(0, 10)   // compression
  ihdr.writeUInt8(0, 11)   // filter
  ihdr.writeUInt8(0, 12)   // interlace
  const ihdrChunk = writeChunk('IHDR', ihdr)

  const rowLen = 1 + width * 4
  const raw = Buffer.alloc(rowLen * height)
  let src = 0
  for (let y = 0; y < height; y++) {
    const off = y * rowLen
    raw[off] = 0 // filter type 0
    for (let x = 0; x < width; x++) {
      const p = off + 1 + x * 4
      raw[p] = rgba[src++]
      raw[p+1] = rgba[src++]
      raw[p+2] = rgba[src++]
      raw[p+3] = rgba[src++]
    }
  }
  const deflated = zlib.deflateSync(raw)
  const idatChunk = writeChunk('IDAT', deflated)
  const iendChunk = writeChunk('IEND', Buffer.alloc(0))
  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk])
}

class Canvas {
  constructor(w, h) {
    this.w = w; this.h = h
    this.px = new Uint8ClampedArray(w * h * 4)
    // default transparent
  }
  fillRoundedRect(x, y, w, h, rad, r, g, b, a = 255) {
    const x0 = x, y0 = y, x1 = x + w, y1 = y + h
    const rr = rad
    for (let yy = Math.max(0, Math.floor(y0)); yy < Math.min(this.h, Math.ceil(y1)); yy++) {
      for (let xx = Math.max(0, Math.floor(x0)); xx < Math.min(this.w, Math.ceil(x1)); xx++) {
        const inCorner = (xx < x0 + rr && yy < y0 + rr && ((xx-(x0+rr))**2 + (yy-(y0+rr))**2 > rr*rr)) ||
                         (xx > x1 - rr && yy < y0 + rr && ((xx-(x1-rr))**2 + (yy-(y0+rr))**2 > rr*rr)) ||
                         (xx < x0 + rr && yy > y1 - rr && ((xx-(x0+rr))**2 + (yy-(y1-rr))**2 > rr*rr)) ||
                         (xx > x1 - rr && yy > y1 - rr && ((xx-(x1-rr))**2 + (yy-(y1-rr))**2 > rr*rr))
        if (!inCorner) this.setPixel(xx, yy, r, g, b, a)
      }
    }
  }
  setPixel(x, y, r, g, b, a = 255) {
    if (x < 0 || y < 0 || x >= this.w || y >= this.h) return
    const i = (y * this.w + x) * 4
    this.px[i] = r; this.px[i+1] = g; this.px[i+2] = b; this.px[i+3] = a
  }
  fillRect(x, y, w, h, r, g, b, a = 255) {
    const x0 = Math.max(0, Math.floor(x)), y0 = Math.max(0, Math.floor(y))
    const x1 = Math.min(this.w, Math.ceil(x + w)), y1 = Math.min(this.h, Math.ceil(y + h))
    for (let yy = y0; yy < y1; yy++) {
      for (let xx = x0; xx < x1; xx++) {
        this.setPixel(xx, yy, r, g, b, a)
      }
    }
  }
  fillCircle(cx, cy, rad, r, g, b, a = 255) {
    const x0 = Math.max(0, Math.floor(cx - rad)), y0 = Math.max(0, Math.floor(cy - rad))
    const x1 = Math.min(this.w, Math.ceil(cx + rad)), y1 = Math.min(this.h, Math.ceil(cy + rad))
    const r2 = rad * rad
    for (let yy = y0; yy < y1; yy++) {
      const dy = yy + 0.5 - cy
      for (let xx = x0; xx < x1; xx++) {
        const dx = xx + 0.5 - cx
        if (dx*dx + dy*dy <= r2) this.setPixel(xx, yy, r, g, b, a)
      }
    }
  }
  fillRightTopTriangle(size, color) {
    const [r,g,b,a] = color
    const s = Math.floor(size)
    for (let y = 0; y < s; y++) {
      const width = s - y
      for (let x = 0; x < width; x++) {
        this.setPixel(this.w - 1 - x, y, r, g, b, a)
      }
    }
  }
}

// Draw LeafLock icon (tile + fold + lock), with optional padding
function drawLeafLock(size, padPx = 0) {
  const bg = [0x4F, 0x46, 0xE5, 255]       // indigo
  const fold = [0x63, 0x66, 0xF1, 255]     // lighter indigo
  const white = [255, 255, 255, 255]
  const dark = [0x11, 0x18, 0x27, 255]

  const c = new Canvas(size, size)
  const inner = size - 2 * padPx
  const ox = padPx
  const oy = padPx
  const scale = inner / 64
  // Background rounded tile (inset)
  const radius = 12 * scale
  c.fillRoundedRect(ox, oy, inner, inner, radius, ...bg)
  // Note fold at top-right (scaled relative to inner)
  // draw fold inside the top-right of inner tile area
  const foldCanvas = new Canvas(inner, inner)
  foldCanvas.fillRightTopTriangle(inner * (12/64), fold)
  // blit foldCanvas into c at (ox, oy)
  for (let y = 0; y < inner; y++) {
    for (let x = 0; x < inner; x++) {
      const i = (y * inner + x) * 4
      const a = foldCanvas.px[i+3]
      if (a) c.setPixel(ox + x, oy + y, foldCanvas.px[i], foldCanvas.px[i+1], foldCanvas.px[i+2], a)
    }
  }

  // Lock body
  const bodyX = ox + 20 * scale, bodyY = oy + 33 * scale, bodyW = 24 * scale, bodyH = 18 * scale
  c.fillRect(bodyX, bodyY, bodyW, bodyH, ...white)

  // Shackle as ring + cut
  const cx = ox + 32 * scale, cy = oy + 28 * scale
  const rOuter = 10 * scale
  const rInner = 6 * scale
  // outer white
  c.fillCircle(cx, cy, rOuter, ...white)
  // inner cut: background color
  c.fillCircle(cx, cy, rInner, ...bg)
  // Hide bottom half to make a U
  c.fillRect(cx - rOuter - 2, cy, (rOuter+2)*2, rOuter + 6*scale, ...bg)

  // Keyhole
  const khR = 3 * scale
  c.fillCircle(ox + 32 * scale, oy + 38 * scale, khR, ...dark)
  c.fillRect(ox + 31 * scale, oy + 40.5 * scale, 2 * scale, 4.5 * scale, ...dark)

  return encodePNG(size, size, c.px)
}

function writeFile(p, buf) {
  mkdirSync(dirname(p), { recursive: true })
  writeFileSync(p, buf)
  console.log(`Wrote ${p} (${buf.length} bytes)`) 
}

// Generate PNG icons with motif
writeFile('frontend/public/apple-touch-icon.png', drawLeafLock(180))
writeFile('frontend/public/icon-192.png', drawLeafLock(192))
writeFile('frontend/public/icon-512.png', drawLeafLock(512))
// Maskable-safe icons (12% padding)
const pad192 = Math.round(192 * 0.12)
const pad512 = Math.round(512 * 0.12)
writeFile('frontend/public/icon-192-maskable.png', drawLeafLock(192, pad192))
writeFile('frontend/public/icon-512-maskable.png', drawLeafLock(512, pad512))

// Generate multi-image favicon.ico (16, 32, 48 PNGs)
function makeICOFromPNGs(images) {
  // images: [{buf, w, h, bpp}]
  const ICONDIR = Buffer.alloc(6)
  ICONDIR.writeUInt16LE(0, 0) // reserved
  ICONDIR.writeUInt16LE(1, 2) // type = icon
  ICONDIR.writeUInt16LE(images.length, 4)

  const entries = []
  let offset = 6 + images.length * 16
  for (const img of images) {
    const { buf, w, h, bpp } = img
    const e = Buffer.alloc(16)
    e.writeUInt8(w === 256 ? 0 : w, 0)
    e.writeUInt8(h === 256 ? 0 : h, 1)
    e.writeUInt8(0, 2) // colors in palette
    e.writeUInt8(0, 3) // reserved
    e.writeUInt16LE(1, 4) // planes
    e.writeUInt16LE(bpp, 6) // bit count
    e.writeUInt32LE(buf.length, 8)
    e.writeUInt32LE(offset, 12)
    offset += buf.length
    entries.push(e)
  }
  const data = Buffer.concat(images.map(i => i.buf))
  return Buffer.concat([ICONDIR, ...entries, data])
}

const ico16 = drawLeafLock(16)
const ico32 = drawLeafLock(32)
const ico48 = drawLeafLock(48)
writeFile('frontend/public/favicon.ico', makeICOFromPNGs([
  { buf: ico16, w: 16, h: 16, bpp: 32 },
  { buf: ico32, w: 32, h: 32, bpp: 32 },
  { buf: ico48, w: 48, h: 48, bpp: 32 },
]))
writeFile('frontend/public/favicon-16.png', drawLeafLock(16))
writeFile('frontend/public/favicon-32.png', drawLeafLock(32))
writeFile('frontend/public/favicon-48.png', drawLeafLock(48))
writeFile('frontend/public/favicon-64.png', drawLeafLock(64))

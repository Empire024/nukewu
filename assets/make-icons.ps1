# Regenerates the Windows Update Control artwork. Run it after changing any of
# the drawing code below, then re-run Check-CriticalUpdates.ps1 -Install so the
# Start Menu shortcuts pick the new files up.
# Draws the Windows Update Control icon at every size natively (no downscaling,
# so small sizes stay crisp) and assembles a multi-resolution .ico by hand.
Add-Type -AssemblyName System.Drawing

function New-RoundedPath {
    param([double]$X,[double]$Y,[double]$W,[double]$H,[double]$R)
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = [float](2*$R)
    $p.AddArc([float]$X,            [float]$Y,             $d, $d, 180, 90)
    $p.AddArc([float]($X+$W-2*$R),  [float]$Y,             $d, $d, 270, 90)
    $p.AddArc([float]($X+$W-2*$R),  [float]($Y+$H-2*$R),   $d, $d,   0, 90)
    $p.AddArc([float]$X,            [float]($Y+$H-2*$R),   $d, $d,  90, 90)
    $p.CloseFigure()
    return $p
}

function Draw-Icon {
    param([int]$S, [string]$Glyph)      # Glyph: 'block' | 'update'

    $bmp = New-Object System.Drawing.Bitmap($S, $S, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g   = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode     = 'AntiAlias'
    $g.PixelOffsetMode   = 'HighQuality'
    $g.CompositingQuality= 'HighQuality'
    $g.Clear([System.Drawing.Color]::Transparent)

    # Below ~24px the rounded tile steals so many pixels that the glyph inside it
    # turns to mush, so the small sizes drop the tile and let the glyph fill the
    # canvas instead. Same trick Windows' own small icons use.
    $tiled = $S -ge 24
    $inset = 0.0
    if ($tiled) {
        $pad = [Math]::Max(0.5, $S * 0.02)
        $rad = [Math]::Max(2.0, $S * 0.19)
        $tile = New-RoundedPath $pad $pad ($S - 2*$pad) ($S - 2*$pad) $rad
        $br = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
                (New-Object System.Drawing.Point(0,0)),
                (New-Object System.Drawing.Point(0,$S)),
                [System.Drawing.Color]::FromArgb(255, 52, 65, 87),
                [System.Drawing.Color]::FromArgb(255, 26, 34, 48))
        $g.FillPath($br, $tile)
        $br.Dispose()
        # hairline edge so the tile reads on a light taskbar as well as a dark one
        $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(140, 128, 148, 178)), ([float]([Math]::Max(1, $S*0.018)))
        $g.DrawPath($pen, $tile); $pen.Dispose(); $tile.Dispose()
        $inset = 0.10       # keep the glyph off the tile edge
    }

    $cx = $S/2.0; $cy = $S/2.0
    $span = $S * (1.0 - 2*$inset)          # the box the glyph gets to live in

    if ($Glyph -eq 'block') {
        $t = [Math]::Max(2.0, $span * 0.19)
        $R = $span/2.0 - $t/2.0
        $ring = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 235, 78, 84)), ([float]$t)
        $g.DrawEllipse($ring, [float]($cx-$R), [float]($cy-$R), [float](2*$R), [float](2*$R))
        $d = $R * 0.7071
        $g.DrawLine($ring, [float]($cx-$d), [float]($cy-$d), [float]($cx+$d), [float]($cy+$d))
        $ring.Dispose()
    } else {
        # download arrow sitting on a base line
        $col = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 61, 194, 101))
        $L = $cx - $span/2.0; $T = $cy - $span/2.0
        $sw = $span * 0.26
        $g.FillRectangle($col, [float]($cx - $sw/2), [float]($T + $span*0.02), [float]$sw, [float]($span*0.46))
        $head = New-Object System.Drawing.Drawing2D.GraphicsPath
        $head.AddPolygon(@(
            (New-Object System.Drawing.PointF ([float]($L + $span*0.11)), ([float]($T + $span*0.40))),
            (New-Object System.Drawing.PointF ([float]($L + $span*0.89)), ([float]($T + $span*0.40))),
            (New-Object System.Drawing.PointF ([float]$cx),               ([float]($T + $span*0.78)))))
        $g.FillPath($col, $head); $head.Dispose()
        $g.FillRectangle($col, [float]($L + $span*0.06), [float]($T + $span*0.88), [float]($span*0.88), [float]([Math]::Max(2, $span*0.12)))
        $col.Dispose()
    }

    $g.Dispose()
    return $bmp
}

function Get-DibBytes {
    param([System.Drawing.Bitmap]$Bmp)
    $w = $Bmp.Width; $h = $Bmp.Height
    $rect = New-Object System.Drawing.Rectangle 0,0,$w,$h
    $data = $Bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $all = New-Object byte[] ($data.Stride * $h)
    [System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $all, 0, $all.Length)
    $Bmp.UnlockBits($data)

    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter $ms
    # BITMAPINFOHEADER - height is doubled because the AND mask follows the XOR bitmap
    $bw.Write([uint32]40); $bw.Write([int32]$w); $bw.Write([int32](2*$h))
    $bw.Write([uint16]1);  $bw.Write([uint16]32); $bw.Write([uint32]0)
    $bw.Write([uint32]($w*$h*4)); $bw.Write([int32]0); $bw.Write([int32]0); $bw.Write([uint32]0); $bw.Write([uint32]0)
    # XOR bitmap, bottom-up BGRA
    for ($y = $h - 1; $y -ge 0; $y--) { $bw.Write($all, $y * $data.Stride, $w * 4) }
    # AND mask, 1bpp, rows padded to 4 bytes. All zero = "use the alpha channel".
    $maskRow = [Math]::Floor(($w + 31) / 32) * 4
    $bw.Write((New-Object byte[] ($maskRow * $h)), 0, $maskRow * $h)
    $bw.Flush()
    return $ms.ToArray()
}

function Write-Ico {
    param([string]$Path, [string]$Glyph)
    $sizes  = 16,20,24,32,40,48,64,128
    $images = @()
    foreach ($s in $sizes) {
        $b = Draw-Icon $s $Glyph
        $images += ,@{ W = $s; H = $s; Data = (Get-DibBytes $b) }
        $b.Dispose()
    }
    # 256 goes in PNG-compressed, which is what Windows expects at that size
    $b = Draw-Icon 256 $Glyph
    $ms = New-Object System.IO.MemoryStream
    $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); $b.Dispose()
    $images += ,@{ W = 256; H = 256; Data = $ms.ToArray() }

    $out = New-Object System.IO.MemoryStream
    $bw  = New-Object System.IO.BinaryWriter $out
    $bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$images.Count)
    $offset = 6 + 16 * $images.Count
    foreach ($i in $images) {
        $bw.Write([byte]($(if ($i.W -ge 256) { 0 } else { $i.W })))
        $bw.Write([byte]($(if ($i.H -ge 256) { 0 } else { $i.H })))
        $bw.Write([byte]0); $bw.Write([byte]0)
        $bw.Write([uint16]1); $bw.Write([uint16]32)
        $bw.Write([uint32]$i.Data.Length); $bw.Write([uint32]$offset)
        $offset += $i.Data.Length
    }
    foreach ($i in $images) { $bw.Write($i.Data, 0, $i.Data.Length) }
    $bw.Flush()
    [System.IO.File]::WriteAllBytes($Path, $out.ToArray())
    Write-Host ("{0}  {1} images, {2:N0} bytes" -f (Split-Path -Leaf $Path), $images.Count, (Get-Item $Path).Length)
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Ico (Join-Path $here 'nukewu-block.ico')  'block'
Write-Ico (Join-Path $here 'nukewu-update.ico') 'update'

# Toast notifications can't use .ico, so the same artwork also goes out as a PNG
# for <image placement="appLogoOverride">.
$png = Draw-Icon 256 'block'
$png.Save((Join-Path $here 'nukewu-block.png'), [System.Drawing.Imaging.ImageFormat]::Png)
$png.Dispose()
Write-Host ("nukewu-block.png  {0:N0} bytes" -f (Get-Item (Join-Path $here 'nukewu-block.png')).Length)

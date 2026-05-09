<?php
// /api/exif.php — Image EXIF metadata extractor (file upload or remote URL).

require __DIR__ . '/_bootstrap.php';

const EXIF_MAX_BYTES   = 10 * 1024 * 1024;       // 10 MB cap
const EXIF_ALLOWED_MIME = ['image/jpeg', 'image/tiff', 'image/png', 'image/webp'];

function exif_parse_fraction(string $s): float {
    if (strpos($s, '/') !== false) {
        [$n, $d] = array_pad(explode('/', $s, 2), 2, '0');
        $d = (float)$d;
        return $d == 0.0 ? 0.0 : ((float)$n) / $d;
    }
    return (float)$s;
}

function exif_dms_to_decimal($parts, ?string $ref): ?float {
    if (!is_array($parts) || count($parts) < 2) return null;
    $deg = exif_parse_fraction((string)($parts[0] ?? '0'));
    $min = exif_parse_fraction((string)($parts[1] ?? '0'));
    $sec = exif_parse_fraction((string)($parts[2] ?? '0'));
    $dec = $deg + $min / 60.0 + $sec / 3600.0;
    if ($ref === 'S' || $ref === 'W') $dec = -$dec;
    return round($dec, 7);
}

function exif_extract_gps(array $exif): ?array {
    // GPS data may live under sectioned key 'GPS' or flat keys when arrays=true is mixed.
    $gps = $exif['GPS'] ?? $exif;
    $lat = exif_dms_to_decimal($gps['GPSLatitude']  ?? null, $gps['GPSLatitudeRef']  ?? null);
    $lng = exif_dms_to_decimal($gps['GPSLongitude'] ?? null, $gps['GPSLongitudeRef'] ?? null);
    if ($lat === null || $lng === null) return null;

    $alt = null;
    if (isset($gps['GPSAltitude'])) {
        $alt = exif_parse_fraction((string)$gps['GPSAltitude']);
        if (!empty($gps['GPSAltitudeRef'])) {
            $altRef = is_string($gps['GPSAltitudeRef']) ? ord($gps['GPSAltitudeRef']) : (int)$gps['GPSAltitudeRef'];
            if ($altRef === 1) $alt = -$alt;
        }
    }

    $timestamp = null;
    if (!empty($gps['GPSDateStamp']) && !empty($gps['GPSTimeStamp']) && is_array($gps['GPSTimeStamp'])) {
        $h = (int)exif_parse_fraction((string)($gps['GPSTimeStamp'][0] ?? '0'));
        $m = (int)exif_parse_fraction((string)($gps['GPSTimeStamp'][1] ?? '0'));
        $s = (int)exif_parse_fraction((string)($gps['GPSTimeStamp'][2] ?? '0'));
        $timestamp = sprintf('%s %02d:%02d:%02d UTC', $gps['GPSDateStamp'], $h, $m, $s);
    }

    return [
        'latitude'      => $lat,
        'longitude'     => $lng,
        'altitude'      => $alt,
        'timestamp_utc' => $timestamp,
        'maps_google'   => 'https://maps.google.com/?q=' . $lat . ',' . $lng,
        'maps_osm'      => 'https://www.openstreetmap.org/?mlat=' . $lat . '&mlon=' . $lng . '#map=17/' . $lat . '/' . $lng,
    ];
}

function exif_pluck(array $section, array $keys): array {
    $out = [];
    foreach ($keys as $k) {
        if (isset($section[$k]) && $section[$k] !== '' && $section[$k] !== []) {
            $out[$k] = is_string($section[$k]) ? trim($section[$k]) : $section[$k];
        }
    }
    return $out;
}

function exif_decode_xp(?string $raw): ?string {
    // XPAuthor / XPComment etc. are UTF-16LE byte strings exposed as comma-joined byte values.
    if ($raw === null || $raw === '') return null;
    $bytes = '';
    foreach (explode(',', $raw) as $b) {
        $bytes .= chr((int)$b);
    }
    $utf8 = @iconv('UTF-16LE', 'UTF-8//IGNORE', $bytes);
    if ($utf8 === false) return null;
    $utf8 = rtrim($utf8, "\0");
    return $utf8 !== '' ? $utf8 : null;
}

function exif_safe_size(string $path): array {
    set_error_handler(static function () {});
    $info = @getimagesize($path);
    restore_error_handler();
    if (!$info) return ['width' => null, 'height' => null, 'mime' => null];
    return ['width' => $info[0], 'height' => $info[1], 'mime' => $info['mime'] ?? null];
}

// ---- Source resolution: file upload or URL download ----

$tmpPath  = null;
$origName = null;
$cleanup  = static function () use (&$tmpPath) {
    if ($tmpPath !== null && is_file($tmpPath)) @unlink($tmpPath);
};
register_shutdown_function($cleanup);

try {
    if (!empty($_FILES['image']) && is_uploaded_file($_FILES['image']['tmp_name'] ?? '')) {
        $f = $_FILES['image'];
        if (($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            spectr_error('Upload failed (error code ' . (int)$f['error'] . ').', 422);
        }
        if (($f['size'] ?? 0) > EXIF_MAX_BYTES) {
            spectr_error('File exceeds 10 MB limit.', 413);
        }
        $tmpPath = tempnam(sys_get_temp_dir(), 'spectr_exif_');
        if ($tmpPath === false || !move_uploaded_file($f['tmp_name'], $tmpPath)) {
            spectr_error('Could not move uploaded file.', 500);
        }
        $origName = basename((string)($f['name'] ?? 'upload'));
    } elseif (!empty($_GET['url'])) {
        $url = (string)$_GET['url'];
        if (!preg_match('#^https?://#i', $url)) {
            spectr_error('URL must start with http:// or https://.', 422);
        }
        $res = spectr_http_get($url);
        if ($res['status'] !== 200 || !$res['body']) {
            spectr_error('Could not download image (HTTP ' . $res['status'] . ').', 502);
        }
        if (strlen($res['body']) > EXIF_MAX_BYTES) {
            spectr_error('Downloaded image exceeds 10 MB limit.', 413);
        }
        $tmpPath = tempnam(sys_get_temp_dir(), 'spectr_exif_');
        if ($tmpPath === false || file_put_contents($tmpPath, $res['body']) === false) {
            spectr_error('Could not save downloaded image to temp dir.', 500);
        }
        $origName = basename(parse_url($url, PHP_URL_PATH) ?: 'remote-image');
    } else {
        spectr_error('Provide an "image" file upload or a "url" parameter.', 422);
    }

    // Validate by content sniffing, not extension.
    $mime = function_exists('mime_content_type') ? mime_content_type($tmpPath) : null;
    if ($mime === false) $mime = null;
    if (!$mime || !in_array($mime, EXIF_ALLOWED_MIME, true)) {
        spectr_error('Unsupported image type (' . ($mime ?: 'unknown') . '). Allowed: ' . implode(', ', EXIF_ALLOWED_MIME), 415);
    }

    $sizeInfo = exif_safe_size($tmpPath);
    $fileSize = filesize($tmpPath) ?: null;

    // exif_read_data only works on JPEG and TIFF; for PNG/WebP it returns false silently.
    $exif = null;
    if (function_exists('exif_read_data')) {
        set_error_handler(static function () {});
        $exif = @exif_read_data($tmpPath, null, true);
        restore_error_handler();
        if ($exif === false) $exif = null;
    }

    $hasExif = is_array($exif) && !empty($exif);

    // Camera / dates / settings can live under multiple sections — flatten lookups.
    $flat = [];
    if (is_array($exif)) {
        foreach ($exif as $sectionName => $sectionVals) {
            if (is_array($sectionVals)) {
                foreach ($sectionVals as $k => $v) $flat[$k] = $flat[$k] ?? $v;
            }
        }
    }

    $camera = exif_pluck($flat, ['Make', 'Model', 'Software', 'DateTime', 'DateTimeOriginal', 'DateTimeDigitized']);
    $settings = exif_pluck($flat, ['ExposureTime', 'FNumber', 'ISOSpeedRatings', 'ISO', 'FocalLength', 'Flash', 'WhiteBalance', 'MeteringMode', 'ExposureProgram']);
    $author = exif_pluck($flat, ['Artist', 'Copyright', 'ImageDescription', 'UserComment']);
    foreach (['XPAuthor', 'XPComment', 'XPSubject', 'XPTitle', 'XPKeywords'] as $xp) {
        if (isset($flat[$xp])) {
            $decoded = exif_decode_xp((string)$flat[$xp]);
            if ($decoded !== null) $author[$xp] = $decoded;
        }
    }
    $device = exif_pluck($flat, ['SerialNumber', 'BodySerialNumber', 'LensModel', 'LensMake', 'LensSerialNumber']);

    $gps = is_array($exif) ? exif_extract_gps($exif) : null;

    $payload = [
        'source'    => $origName,
        'basic'     => [
            'file_name'   => $origName,
            'file_size'   => $fileSize,
            'mime_type'   => $mime,
            'image_width' => $sizeInfo['width'],
            'image_height'=> $sizeInfo['height'],
            'has_exif'    => $hasExif,
        ],
        'camera'    => $camera,
        'settings'  => $settings,
        'author'    => $author,
        'device'    => $device,
        'gps'       => $gps,
        'sections'  => is_array($exif) ? array_keys($exif) : [],
        'raw_exif'  => $exif,
    ];

    spectr_log_scan('exif:' . ($origName ?: 'upload'), 'exif', $hasExif, $payload);
    spectr_ok($payload, $origName);
} finally {
    $cleanup();
}

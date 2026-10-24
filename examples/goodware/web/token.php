<?php
// yaraci lab fixture - synthetic and benign
function decode_token(string $t): array {
    return json_decode(base64_decode(strtr($t, '-_', '+/')), true) ?? [];
}

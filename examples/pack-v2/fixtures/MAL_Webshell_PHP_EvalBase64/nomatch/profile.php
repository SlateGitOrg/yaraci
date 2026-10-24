<?php
// yaraci lab fixture - synthetic and benign
// Decoding user data is fine; evaluating it is not.
$profile = json_decode(base64_decode($_COOKIE['profile'] ?? ''), true);
echo htmlspecialchars($profile['name'] ?? 'guest');

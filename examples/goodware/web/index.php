<?php
// yaraci lab fixture - synthetic and benign
$items = json_decode(file_get_contents('items.json'), true);
foreach ($items as $item) { echo '<li>' . htmlspecialchars($item['name']) . '</li>'; }

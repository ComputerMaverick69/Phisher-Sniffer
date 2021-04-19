<?php

header("Access-Control-Allow-Origin: *");

// Get the HTML Contents of the URL that is being parsed. This is the input data used by the python code.
$site_url = $_POST['url'];

// Parsed HTML Content from URL
$html = file_get_contents($site_url);
// echo $htmk;

$bytes = file_put_contents('markup.txt', $html);

// Replace the path with the path of your python3.x Installation

// Get python3 path automatically (macOS)
$python_path = exec("which python3 2>&1");

// Execute the python3 decision
$decision = exec("$python_path test.py $site 2>&1");
echo $decision;

?>
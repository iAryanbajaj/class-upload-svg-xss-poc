
<h1>Stored XSS via SVG Upload in verot/class.upload.php</h1>

<h2>Overview</h2>

<p>
This repository documents a Stored Cross-Site Scripting (XSS)
vulnerability in the <strong>verot/class.upload.php</strong>
PHP file-upload library.
</p>

<p>
The vulnerability allows SVG files containing active script content
to bypass the default <code>no_script</code> protection and remain
executable when accessed from the website's origin.
</p>

<ul>
  <li><strong>Vulnerability Type:</strong> Stored Cross-Site Scripting (XSS)</li>
  <li><strong>CWE:</strong> CWE-79</li>
  <li><strong>Affected Product:</strong> verot/class.upload.php</li>
</ul>

<h2>Affected Versions</h2>

<ul>
  <li>1.0.0 – 1.1.2 (1.x branch)</li>
  <li>1.0.0 – 2.1.6 (2.x branch)</li>
</ul>

<h2>Fixed Versions</h2>

<ul>
  <li>2.1.7 (2.x branch)</li>
  <li>1.1.3 (1.x branch)</li>
</ul>

<p><strong>Fix Published:</strong> November 6, 2026</p>

<h2>Technical Details</h2>

<p>
The default <code>no_script</code> protection handles several
dangerous file extensions, including HTML, HTM, JavaScript and PHP.
However, SVG is missing from the dangerous extension list.
</p>

<p>
Because SVG files can contain active script content, an uploaded SVG
may retain its original extension and content instead of being
neutralized.
</p>

<p>
When the uploaded SVG is accessed through a browser in the vulnerable
website's origin, its script content can execute.
</p>

<h2>Root Cause</h2>

<ul>
  <li>SVG is missing from the <code>$dangerous</code> extension list.</li>
  <li>The default <code>$allowed</code> list includes the <code>image/*</code> wildcard.</li>
  <li>SVG MIME type is <code>image/svg+xml</code>.</li>
  <li>The <code>no_script</code> rename condition does not catch this MIME type.</li>
  <li>SVG is not included in the GD-based raster image processing pipeline.</li>
</ul>

<h2>Proof of Concept</h2>

<p>
The <code>poc_matrix.php</code> file in this repository provides
a self-contained test harness.
</p>

<p>The test matrix covers:</p>

<ul>
  <li>SVG containing a script tag.</li>
  <li>SVG containing an <code>onload</code> attribute.</li>
  <li>SVG containing a <code>foreignObject</code> with an event handler.</li>
  <li>HTML control test to verify the expected <code>no_script</code> behavior.</li>
</ul>

<p>
The tests compare uploaded and stored file hashes to verify whether
the uploaded content was modified.
</p>

<h2>Verification</h2>

<p>
Runtime testing was performed using PHP 8.5.8 with the fileinfo
extension enabled.
</p>

<p><strong>Tested Versions:</strong></p>

<ul>
  <li>1.0.3</li>
  <li>2.0.4</li>
  <li>2.1.5</li>
  <li>2.1.6</li>
  <li>Master branch</li>
</ul>

<p>
The issue was re-tested against the fixed releases 2.1.7 and 1.1.3.
</p>

<h2>References</h2>

<ul>
  <li>
    Project:
    <a href="https://github.com/verot/class.upload.php">
      verot/class.upload.php
    </a>
  </li>
  <li>
    <a href="https://github.com/verot/class.upload.php/releases/tag/2.1.7">
      Release 2.1.7
    </a>
  </li>
  <li>
    <a href="https://github.com/verot/class.upload.php/releases/tag/1.1.3">
      Release 1.1.3
    </a>
  </li>
  <li>
    <a href="https://github.com/verot/class.upload.php/commit/b26bbd54114537bc21671fe570cc4077b086c483">
      Fix Commit
    </a>
  </li>
</ul>

<h2>Researcher</h2>

<p>
<strong>Aryan Bajaj</strong><br>
Independent Security Researcher<br>
GitHub:
<a href="https://github.com/iAryanbajaj">@iAryanbajaj</a>
</p>

<h2>Disclaimer</h2>

<p>
This repository is intended for authorized security research,
vulnerability verification and educational purposes only.
</p>

<p>
Test only against software and environments you own or have
explicit permission to assess.
</p>

<p>
Use the fixed versions to protect affected applications.
</p>

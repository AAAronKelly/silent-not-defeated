# Silent, Not Defeated

Website for *Silent, Not Defeated*, a memoir by Dermot Kelly. A static site hosted on GitHub Pages.

Until the book is released the site sits behind a password. `index.html` is a small gate page holding an encrypted copy of the real site, which is decrypted in the browser once the password is entered. The unencrypted source is kept out of this repository until launch.

To rebuild the gate after editing the source:

    powershell -ExecutionPolicy Bypass -File protect.ps1 -Password "your password"

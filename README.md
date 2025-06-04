<a href="https://github.com/Picocrypt/Picocrypt/actions/workflows/build-windows.yml"><img src="https://github.com/Picocrypt/Picocrypt/actions/workflows/build-windows.yml/badge.svg"></a>
<a href="https://github.com/Picocrypt/Picocrypt/actions/workflows/build-macos.yml"><img src="https://github.com/Picocrypt/Picocrypt/actions/workflows/build-macos.yml/badge.svg"></a>
<a href="https://github.com/Picocrypt/Picocrypt/actions/workflows/build-linux.yml"><img src="https://github.com/Picocrypt/Picocrypt/actions/workflows/build-linux.yml/badge.svg"></a>
<a href="https://github.com/Picocrypt/Picocrypt/actions/workflows/codeql-analysis.yml"><img src="https://github.com/Picocrypt/Picocrypt/actions/workflows/codeql-analysis.yml/badge.svg"></a>

<p align="center"><img align="center" src="/images/logo.svg" width="512" alt="Picocrypt"></p> 

Picocrypt is a very small (hence <i>Pico</i>), very simple, yet very secure encryption tool that you can use to protect your files. It's designed to be the <i>go-to</i> tool for encryption, with a focus on security, simplicity, and reliability. Picocrypt uses the secure XChaCha20 cipher and the Argon2id key derivation function to provide a high level of security, even from three-letter agencies like the NSA. <strong>Your privacy and security is under attack. Take it back with confidence by protecting your files with Picocrypt.</strong>

<br>
<p align="center"><img align="center" src="/images/screenshot.png" width="318" alt="Picocrypt"></p>

# Downloads
**Make sure to only download Picocrypt from this repository** to ensure that you get the authentic and backdoor-free Picocrypt. When sharing Picocrypt with others, be sure to link to this repository to prevent any confusion.

**Beware of picocrypt.org, which claims to be the official website for this project! Remember, there is no official website for Picocrypt.** Even if this self-proclaimed website is taken down, I will not remove this message; let it be a real-world warning to stay vigilant.

## Windows
Picocrypt for Windows is as simple as it gets. To download the latest, standalone, and portable executable for Windows, click <a href="https://github.com/Picocrypt/Picocrypt/releases/latest/download/Picocrypt.exe">here</a>. If Microsoft Defender or your antivirus flags Picocrypt as a virus, please do your part and submit it as a false positive for the betterment of everyone.

## macOS
Picocrypt for macOS is very simple as well. Download Picocrypt <a href="https://github.com/Picocrypt/Picocrypt/releases/latest/download/Picocrypt.dmg">here</a>, open the container, and drag Picocrypt to your Applications. You may need to manually trust the app from a terminal and control-click on the app if macOS prevents you from opening it:
```
xattr -d com.apple.quarantine /Applications/Picocrypt.app
```

Or, if you use Homebrew, you can add a tap and install Picocrypt:
```
brew tap Picocrypt/picocrypt
brew install picocrypt --no-quarantine
```

## Linux
To use Picocrypt on Linux, you can download the raw binary <a href="https://github.com/Picocrypt/Picocrypt/releases/latest/download/Picocrypt">here</a> (you may need to install the packages below). Alternatively, you can try the <a href="https://github.com/Picocrypt/Picocrypt/releases/latest/download/Picocrypt.deb">.deb</a>, <a href="https://flathub.org/apps/io.github.picocrypt.Picocrypt">Flatpak</a>, run Picocrypt through Wine, or compile from source using the instructions in the `src/` directory.
```
sudo apt install -y libc6 libgcc-s1 libgl1 libgtk-3-0 libstdc++6 libx11-6
```

## CLI
A command-line interface is available for Picocrypt <a href="https://github.com/Picocrypt/CLI">here</a>. It can encrypt and decrypt files, folders, and globs, and supports paranoid mode and Reed-Solomon encoding. You can use it on systems that don't have a GUI or can't run the GUI app, or to write automated shell scripts for backups, etc.

## Web
A functionally limited web app is available <a href="https://picocrypt.github.io/">here</a> which allows you to encrypt and decrypt standard Picocrypt volumes (no advanced features or keyfiles) on any modern browser, including mobile devices. It's a simple, future-proof way to encrypt files that should work indefinitely due to the web's stable nature. Note that you can only encrypt single files up to a maximum size of 1 GiB.

## Mobile 🚧
An experimental project <a href="https://github.com/Picocrypt/PicoGo">PicoGo</a> is a community-developed port of Picocrypt to platforms like Android and iOS using the Fyne GUI library. Feel free to try it out, but keep in mind that it is *not* part of the official core Picocrypt project (like the platforms listed above) and thus not subject to the same scrutiny and standards that the core project is. So, **use it with caution and diligence** during its experimental phase.

# Why Picocrypt?
Why should you use Picocrypt instead of VeraCrypt, 7-Zip, BitLocker, or Cryptomator? Here are a few reasons why you should choose Picocrypt:
<ul>
	<li>Unlike BitLocker and most cloud services, Picocrypt and its dependencies are completely open-source and auditable. You can verify for yourself that there aren't any backdoors or flaws. In fact, Picocrypt was audited by Radically Open Security in 2024 and no major security issues were discovered (you can read the full report <a href="https://github.com/Picocrypt/storage/blob/main/Picocrypt.Audit.Report.pdf">here</a>).</li>
	<li>Picocrypt is <i>tiny</i>. While Cryptomator is over 50 MiB and VeraCrypt is over 20 MiB, Picocrypt sits at just 3 MiB, about the size of a medium-resolution photo. And that's not all - Picocrypt is portable (doesn't need to be installed) and doesn't require administrator/root privileges.</li>
	<li>Picocrypt is easier and more productive to use than VeraCrypt. To encrypt files with VeraCrypt, you'd have to spend a minute or two just setting up a volume. With Picocrypt's simple UI, all you have to do is drag and drop your files, enter a password, and hit Encrypt. All the complex procedures are handled by Picocrypt internally. Who said secure encryption can't be simple?</li>
	<li>Picocrypt is designed for security. 7-Zip is an archive utility and not an encryption tool, so its focus is not on security. Picocrypt, however, is built with security as the number one priority. Every part of Picocrypt exists for a reason and anything that could impact the security of Picocrypt is removed. Picocrypt is built with cryptography you can trust.</li>
	<li>Picocrypt authenticates data in addition to protecting it, preventing hackers from maliciously modifying sensitive data. This is useful when you are sending encrypted files over an insecure channel and want to be sure that it arrives untouched.</li>
	<li>Picocrypt actively protects header data from corruption by adding extra Reed-Solomon parity bytes, so if part of a volume's header (which contains important cryptographic components) corrupts (e.g., hard drive bit rot), Picocrypt can still recover the header and decrypt your data with a high success rate. Picocrypt can also encode the entire volume with Reed-Solomon to prevent any corruption to your important files.</li>
</ul>

# Comparison
Here's how Picocrypt compares to other popular encryption tools.

|                | Picocrypt      | VeraCrypt      | 7-Zip GUI      | BitLocker      | Cryptomator    |
| -------------- | -------------- | -------------- | -------------- | -------------- | -------------- |
| Free           |✅ Yes         |✅ Yes          |✅ Yes         |✅ Bundled      |✅ Yes         |
| Open Source    |✅ GPLv3       |✅ Multi        |✅ LGPL        |❌ No           |✅ GPLv3       |
| Cross-Platform |✅ Yes         |✅ Yes          |❌ No          |❌ No           |✅ Yes         |
| Size           |✅ 3 MiB       |❌ 20 MiB       |✅ 2 MiB       |✅ N/A          |❌ 50 MiB      |
| Portable       |✅ Yes         |✅ Yes          |❌ No          |✅ Yes          |❌ No          |
| Permissions    |✅ None        |❌ Admin        |❌ Admin       |❌ Admin        |❌ Admin       |
| Ease-Of-Use    |✅ Easy        |❌ Hard         |✅ Easy        |✅ Easy         |🟧 Medium      |
| Cipher         |✅ XChaCha20   |✅ AES-256      |✅ AES-256     |🟧 AES-128      |✅ AES-256     |
| Key Derivation |✅ Argon2      |🟧 PBKDF2       |❌ SHA-256     |❓ Unknown      |✅ Scrypt      |
| Data Integrity |✅ Always      |❌ No           |❌ No          |❓ Unknown      |✅ Always      |
| Deniability    |✅ Supported   |✅ Supported    |❌ No          |❌ No           |❌ No          |
| Reed-Solomon   |✅ Yes         |❌ No           |❌ No          |❌ No           |❌ No          |
| Compression    |✅ Yes         |❌ No           |✅ Yes         |✅ Yes          |❌ No          |
| Telemetry      |✅ None        |✅ None         |✅ None        |❓ Unknown      |✅ None        |
| Audited        |✅ [Yes](https://github.com/Picocrypt/storage/blob/main/Picocrypt.Audit.Report.pdf)       |✅ Yes          |❌ No          |❓ Unknown      |✅ Yes         |

Keep in mind that while Picocrypt does most things better than other tools, it's not a one-size-fits-all and doesn't try to be. There are use cases such as full-disk encryption where VeraCrypt and BitLocker would be a better choice. So while Picocrypt is a great choice for the majority of people, you should still do your own research and use what's best for you.

# Features
Picocrypt is a very simple tool, and most users will intuitively understand how to use it in a few seconds. On a basic level, simply dropping your files, entering a password, and hitting Encrypt is all that's needed to encrypt your files. Dropping the output back into Picocrypt, entering the password, and hitting Decrypt is all that's needed to decrypt those files. Pretty simple, right?

While being simple, Picocrypt also strives to be powerful in the hands of knowledgeable and advanced users. Thus, there are some additional options that you may use to suit your needs.
<ul>
	<li><strong>Password generator</strong>: Picocrypt provides a secure password generator that you can use to create cryptographically secure passwords. You can customize the password length, as well as the types of characters to include.</li>
	<li><strong>Comments</strong>: Use this to store notes, information, and text along with the file (<strong>it won't be encrypted</strong>). For example, you can put a description of the file you're encrypting before sending it to someone. When the person you sent it to drops the file into Picocrypt, your description will be shown to that person. <strong>Comments are not authenticated, meaning it can be freely modified by an attacker. Thus, it should only be used for informational purposes in trusted environments.</strong></li>
	<li><strong>Keyfiles</strong>: Picocrypt supports the use of keyfiles as an additional form of authentication (or the only form of authentication). Any file can be used as a keyfile, and a secure keyfile generator is provided for convenience. Not only can you use multiple keyfiles, but you can also require the correct order of keyfiles to be present for a successful decryption to occur. A particularly good use case of multiple keyfiles is creating a shared volume, where each person holds a keyfile, and all of them (and their keyfiles) must be present to decrypt the shared volume. By checking the "Require correct order" box and dropping your keyfile in last, you can also ensure that you'll always be the one clicking the Decrypt button.</li>
	<li><strong>Paranoid mode</strong>: Using this mode will encrypt your data with both XChaCha20 and Serpent in a cascade fashion, and use HMAC-SHA3 to authenticate data instead of BLAKE2b. Argon2 parameters will be increased significantly as well. This is recommended for protecting top-secret files and provides the highest level of practical security attainable. For a hacker to break into your encrypted data, both the XChaCha20 cipher and the Serpent cipher must be broken, assuming you've chosen a good password. It's safe to say that in this mode, your files are impossible to crack. Keep in mind, however, that this mode is slower and isn't really necessary unless you're a government agent with classified data or a whistleblower under threat.</li>
	<li><strong>Reed-Solomon</strong>: This feature is very useful if you are planning to archive important data on a cloud provider or external medium for a long time. If checked, Picocrypt will use the Reed-Solomon error correction code to add 8 extra bytes for every 128 bytes of data to prevent file corruption. This means that up to ~3% of your file can corrupt and Picocrypt will still be able to correct the errors and decrypt your files with no corruption. Of course, if your file corrupts very badly (e.g., you dropped your hard drive), Picocrypt won't be able to fully recover your files, but it will try its best to recover what it can. Note that this option will slow down encryption and decryption speeds significantly.</li>
	<li><strong>Force decrypt</strong>: Picocrypt automatically checks for file integrity upon decryption. If the file has been modified or is corrupted, Picocrypt will automatically delete the output for the user's safety. If you would like to override these safeguards, check this option. Also, if this option is checked and the Reed-Solomon feature was used on the encrypted volume, Picocrypt will attempt to recover as much of the file as possible during decryption.</li>
	<li><strong>Split into chunks</strong>: Don't feel like dealing with gargantuan files? No worries! With Picocrypt, you can choose to split your output file into custom-sized chunks, so large files can become more manageable and easier to upload to cloud providers. Simply choose a unit (KiB, MiB, GiB, or TiB) and enter your desired chunk size for that unit. To decrypt the chunks, simply drag one of them into Picocrypt and the chunks will be automatically recombined during decryption.</li>
	<li><strong>Compress files</strong>: By default, Picocrypt uses a zip file with no compression to quickly merge files together when encrypting multiple files. If you would like to compress these files, however, simply check this box and the standard Deflate compression algorithm will be applied during encryption.</li>
	<li><strong>Deniability</strong>: Picocrypt volumes typically follow an easily recognizable header format. However, if you want to hide the fact that you are encrypting your files, enabling this option will provide you with plausible deniability. The output volume will indistinguishable from a stream of random bytes, and no one can prove it is a volume without the correct password. This can be useful in an authoritarian country where the only way to transport your files safely is if they don't "exist" in the first place. Keep in mind that this mode slows down encryption and decryption speeds, requires you to manually rename the volume afterward, renders comments useless, and also voids the extra security precautions of the paranoid mode, so you should only use it if absolutely necessary.</li>
	<li><strong>Recursively</strong>: If you want to encrypt and/or decrypt a large set of files individually, this option will tell Picocrypt to go through every recursive file that you drop in and encrypt/decrypt it separately. This is useful, for example, if you are encrypting thousands of large documents and want to be able to decrypt any one of them in particular without having to download and decrypt the entire set of documents. Keep in mind that this is a very complex feature that should only be used if you know what you are doing.</li>
</ul>

# Security
For more information on how Picocrypt handles cryptography, see <a href="Internals.md">Internals</a> for the technical details. If you're worried about the safety of me or this project, let me assure you that this repository won't be hijacked or backdoored. I have 2FA (TOTP) enabled on all accounts with a tie to Picocrypt (GitHub, etc.), in addition to full-disk encryption on all of my portable devices. For further hardening, Picocrypt uses my isolated forks of dependencies and I fetch upstream only when I have taken a look at the changes and believe that there aren't any security issues. This means that if a dependency gets hacked or deleted by the author, Picocrypt will be using my fork of it and remain completely unaffected. I've also meticulously gone through every single setting in the Picocrypt organization and repos, locking down access behind multiple layers of security such as read-only base-level member permissions, required PRs and mandatory approvals (which no one can do but me), mandatory CODEOWNERS approvals, and I'm the only member of the Picocrypt organization and repos (except for PicoGo). You can feel confident about using Picocrypt as long as you understand:

<strong>Picocrypt operates under the assumption that the host machine it is running on is safe and trusted. If that is not the case, no piece of software will be secure, and you will have much bigger problems to worry about. As such, Picocrypt is designed for the offline security of volumes and does not attempt to protect against side-channel analysis.</strong>

# Donations
When I was actively developing Picocrypt, I accepted donations, but now that Picocrypt is complete and production-ready, there's no need anymore. Instead, take your time and effort to share the love of Picocrypt with others. Donations are nice, but being able to help others is a lot more valuable to me than a few spare dollars. Knowing that Picocrypt is helping people secure their files is plenty enough for me.

# FAQ
**Does the "Delete files" feature shred files?**

No, it doesn't shred any files and just deletes them as your file manager would. On modern storage mediums like SSDs, there is no such thing as shredding a file since wear leveling makes it impossible to overwrite a particular sector. Thus, to prevent giving users a false sense of security, Picocrypt doesn't include any shredding features at all.

**Is Picocrypt quantum-secure?**

Yes, Picocrypt is secure against quantum computers. All of the cryptography used in Picocrypt works off of a private key, and private-key cryptography is considered to be resistant against all current and future developments, including quantum computers.

# Acknowledgements
A thank you from the bottom of my heart to the significant contributors on [Open Collective](https://opencollective.com/picocrypt):
<ul>
	<li><strong>Mikołaj ($1674)</strong></li>
	<li><strong>Guest ($842)</strong></li>
	<li><strong>YellowNight ($818)</strong></li>
	<li>Incognito ($135)</li>
	<li>akp ($98)</li>
	<li>JC ($90)</li>
	<li>evelian ($50)</li>
	<li>jp26 ($50)</li>
	<li>guest-116103ad ($50)</li>
	<li>Guest ($27)</li>
	<li>Gittan Pade ($25)</li>
	<li>Pokabu ($20)</li>
	<li>oli ($20)</li>
	<li>Bright ($20)</li>
	<li>Incognito ($20)</li>
	<li>Guest ($20)</li>
	<li>JokiBlue ($20)</li>
	<li>Guest ($20)</li>
	<li>Markus ($15)</li>
	<li>EN ($15)</li>
	<li>Guest ($13)</li>
	<li>Tybbs ($10)</li>
	<li>N. Chin ($10)</li>
	<li>Manjot ($10)</li>
	<li>Phil P. ($10)</li>
	<li>Raymond ($10)</li>
	<li>Cohen ($10)</li>
	<li>EuA ($10)</li>
	<li>geevade ($10)</li>
	<li>Guest ($10)</li>
	<li>Hilebrinest ($10)</li>
	<li>gabu.gu ($10)</li>
	<li>Boat ($10)</li>
	<li>Guest ($10)</li>
</ul>
<!-- Last updated July 12, 2024 -->

Also, a huge thanks to the following people who were the first to donate and support Picocrypt:
<ul>
	<li>W.Graham</li>
	<li>N. Chin</li>
	<li>Manjot</li>
	<li>Phil P.</li>
	<li>E. Zahard</li>
</ul>

Finally, thanks to these people/organizations for helping me out when needed:
<ul>
	<li>[ REDACTED ] for helping me create an AppImage for Picocrypt</li>
	<li>u/Upstairs-Fishing867 for helping me test PGP signatures</li>
	<li>u/greenreddits for constant feedback and support</li>
	<li>u/Tall_Escape for helping me test Picocrypt</li>
	<li>u/NSABackdoors for doing plenty of testing</li>
	<li>@samuel-lucas6 for feedback, suggestions, and support</li>
	<li>@AsuxAX and @Minibus93 for testing new features</li>
	<li>@mdanish-kh and @stephengillie for WinGet package</li>
	<li>@Retengart for helping create the Flatpak</li>
	<li><a href="https://privacyguides.org">Privacy Guides</a> for listing Picocrypt</li>
	<li><a href="https://www.radicallyopensecurity.com/">Radically Open Security</a> for auditing Picocrypt</li>
	<li>You?</li>
</ul>

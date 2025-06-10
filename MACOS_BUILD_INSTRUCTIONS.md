# Building Picocrypt on macOS

This guide provides instructions on how to build Picocrypt from source on a macOS system.

## Prerequisites

1.  **Xcode Command Line Tools:**
    If you haven't already, install the Xcode Command Line Tools. Open Terminal and run:
    ```bash
    xcode-select --install
    ```
    Follow the on-screen prompts.

2.  **Homebrew:**
    Homebrew is a package manager for macOS. If you don't have it, install it by following the instructions at [brew.sh](https://brew.sh/).

3.  **Go Programming Language:**
    *   **Installation:** It's recommended to install the latest stable version of Go. You can download it from the [official Go website](https://golang.org/dl/) or install it via Homebrew:
        ```bash
        brew install go
        ```
    *   **Environment Setup (if not using Homebrew's Go):** Ensure your `GOPATH` and `GOROOT` environment variables are set up correctly, and that `$GOPATH/bin` and `$GOROOT/bin` are in your `PATH`. If you installed Go via Homebrew, this is usually handled automatically. You can check your Go environment with `go env`.

4.  **Git:**
    If not already installed (usually comes with Xcode Command Line Tools), install Git:
    ```bash
    brew install git
    ```

5.  **Required Libraries (GLFW & GLEW):**
    Picocrypt's GUI depends on GLFW and GLEW. Install them using Homebrew:
    ```bash
    brew install glfw glew
    ```

## Build Steps

1.  **Clone the Repository:**
    Open Terminal and navigate to the directory where you want to store the Picocrypt source code. Then clone the repository:
    ```bash
    git clone https://github.com/Picocrypt/Picocrypt.git
    cd Picocrypt
    ```

2.  **Navigate to the Source Directory:**
    The main Go source code is located in the `src` directory.
    ```bash
    cd src
    ```

3.  **Download Dependencies:**
    Picocrypt uses Go modules to manage its dependencies. Download them using:
    ```bash
    go mod download
    ```
    This command inspects the `go.mod` file and downloads all necessary libraries.

4.  **Compile the Application:**
    Build the Picocrypt application. The `-ldflags="-s -w"` flags help reduce the binary size by stripping debug symbols. `CGO_ENABLED=1` is necessary as Picocrypt uses Cgo for its GUI components.
    ```bash
    CGO_ENABLED=1 go build -v -ldflags="-s -w" -o Picocrypt Picocrypt.go
    ```
    The `-v` flag enables verbose output, showing the packages as they are compiled. The `-o Picocrypt` flag specifies the output file name.

    Upon successful compilation, you will find an executable file named `Picocrypt` in the `src` directory.

## Packaging (Optional - Creating a .app Bundle and .dmg)

The following steps replicate the process used in the GitHub Actions workflow to create a standard macOS application bundle (`.app`) and a disk image (`.dmg`).

1.  **Prepare the .app Bundle Structure:**
    The Picocrypt repository includes a template for the `.app` bundle.
    *   Go back to the root directory of the cloned repository:
        ```bash
        cd ..
        ```
    *   The template `Picocrypt.app.zip` is usually located in `dist/macos/`. For a manual build, you might need to ensure this path is correct or download/copy this template if it's not present directly. Assuming it's in `dist/macos/`:
        ```bash
        cp dist/macos/Picocrypt.app.zip .
        unzip -d Picocrypt.app Picocrypt.app.zip
        rm Picocrypt.app.zip
        ```
        This creates a `Picocrypt.app` directory with the necessary bundle structure.

2.  **Move the Compiled Binary:**
    Move the `Picocrypt` executable you compiled in the `src` directory into the `.app` bundle:
    ```bash
    mv src/Picocrypt Picocrypt.app/Contents/MacOS/Picocrypt
    ```

3.  **Create the .dmg Disk Image:**
    *   Create a temporary directory to hold the `.app` bundle for DMG creation:
        ```bash
        mkdir out
        cp -R Picocrypt.app out/
        ```
    *   Use `hdiutil` to create the DMG:
        ```bash
        hdiutil create Picocrypt.dmg -volname Picocrypt -fs APFS -format UDZO -srcfolder out
        ```
        This will create `Picocrypt.dmg` in the root of the repository.

    *   Clean up the temporary directory:
        ```bash
        rm -rf out
        rm -rf Picocrypt.app
        ```

You should now have a `Picocrypt.dmg` file ready for distribution or installation. The standalone `Picocrypt` executable (from `src/Picocrypt`) can also be run directly if you don't need the `.app` bundle.

## Running Picocrypt

*   **Directly:** You can run the compiled binary from the `src` directory:
    ```bash
    ./src/Picocrypt
    ```
*   **From .app Bundle:** If you created the `.app` bundle, you can run it by double-clicking `Picocrypt.app` in Finder, or from Terminal:
    ```bash
    open Picocrypt.app
    ```
*   **From .dmg:** Open `Picocrypt.dmg`, and then drag `Picocrypt.app` to your Applications folder. Run it from there.

This completes the build process for Picocrypt on macOS.

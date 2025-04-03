if (data.lendingInfo.shouldProtectImages) {
      options.renderPageURI = async function deobfuscateImage(imgEl, src) {
        const response = await fetch(src, { credentials: 'include' });
        const obfuscationHeader = response.headers.get('X-Obfuscate');
        // If no obfuscate header, then we don't need to do anything
        if (!obfuscationHeader) {
          imgEl.src = src;
          return;
        }
        const contentType = response.headers.get('content-type');

        // Read the entire image in one chunk
        const imageBuffer = await response.arrayBuffer();

        // Decrypt the first 1024 bytes of the image
        const [version, counter] = obfuscationHeader.split('|');
        if (version !== '1') {
          throw new Error('Unsupported obfuscation version');
        }

        const aesKey = src.replace(/https?:\/\/.*?\//, '/');
        const decryptedBuffer = await decrypt(imageBuffer.slice(0, 1024), aesKey, counter);

        // Replace the first 1024 bytes of the image with the decrypted bytes
        const decryptedImageBuffer = new Uint8Array(imageBuffer);
        decryptedImageBuffer.set(new Uint8Array(decryptedBuffer), 0);
        const decryptedBlob = new Blob([decryptedImageBuffer], { type: contentType });

        // Set the image source to the decrypted image
        imgEl.addEventListener('load', ev => URL.revokeObjectURL(imgEl.src), { once: true });
        imgEl.src = URL.createObjectURL(decryptedBlob);
      }

      async function decrypt(buffer, aesKey, counter) {
        const aesKeyArr = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(aesKey));

        // Un-base64 the encrypted counter
        const key = await crypto.subtle.importKey("raw", aesKeyArr.slice(0, 16), "AES-CTR", false, ["decrypt"]);
        return await crypto.subtle.decrypt(
          {
            name: "AES-CTR",
            length: 64,
            counter: new Uint8Array(atob(counter).split('').map(char => char.charCodeAt(0))),
          },
          key,
          buffer,
        );
      }
    }
package com.tara.passkey.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

public class DecryptedRequestWrapper extends HttpServletRequestWrapper {
    private final byte[] body;

    public DecryptedRequestWrapper(HttpServletRequest request, byte[] body) {
        super(request);
        this.body = body;
    }

    @Override
    public ServletInputStream getInputStream() {
        InputStream inputStream = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override
            public int read() throws IOException {
                return inputStream.read();
            }

            @Override
            public boolean isFinished() {
                try {
                    return inputStream.available() == 0;
                } catch (IOException ex) {
                    return true;
                }
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
            }
        };
    }

    @Override
    public int getContentLength() {
        return body.length;
    }

    @Override
    public long getContentLengthLong() {
        return body.length;
    }
}

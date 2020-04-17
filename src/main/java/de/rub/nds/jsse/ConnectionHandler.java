package de.rub.nds.jsse;

import java.io.*;
import java.net.Socket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.Strings;

public class ConnectionHandler implements Runnable {

    private final static Logger LOGGER = LogManager.getLogger(ConnectionHandler.class.getName());

    private final Socket applicationSocket;

    /**
     * ConnectionHandler constructor
     * 
     * @param socket
     *            - The socket of the connection
     */
    public ConnectionHandler(final Socket socket) {
        applicationSocket = socket;
    }

    @Override
    public void run() {

        LOGGER.debug("new Thread started");

        try {
            InputStream in = applicationSocket.getInputStream();
            OutputStream out = applicationSocket.getOutputStream();
            out.write(Strings.toByteArray("Hello"));
        } catch (IOException e) {
            LOGGER.debug(e.getLocalizedMessage(), e);
        } finally {
            try {
                applicationSocket.close();
            } catch (final IOException ioe) {
                LOGGER.debug(ioe.getLocalizedMessage(), ioe);
            }
        }
    }
}
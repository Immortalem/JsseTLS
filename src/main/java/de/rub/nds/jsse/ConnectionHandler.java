package de.rub.nds.jsse;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
            final BufferedReader br = new BufferedReader(new InputStreamReader(applicationSocket.getInputStream()));
            final BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(applicationSocket.getOutputStream()));
            String line = "";
            while ((line = br.readLine()) != null) {
                LOGGER.debug(line);
                bw.write("ack");
                bw.flush();
            }
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
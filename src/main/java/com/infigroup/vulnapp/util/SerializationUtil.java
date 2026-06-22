package com.infigroup.vulnapp.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

/**
 * Java native deserialization helper.
 */
public final class SerializationUtil {

    private SerializationUtil() {
    }

    /** SINK (CWE-502): deserializes attacker-controlled bytes. */
    public static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois =
                     new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }
}

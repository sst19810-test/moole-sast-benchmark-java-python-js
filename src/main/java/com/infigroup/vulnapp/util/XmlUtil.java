package com.infigroup.vulnapp.util;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;

/**
 * XML parsing helper. The default factory configuration resolves external
 * entities and DTDs, so this is an XXE sink.
 */
public final class XmlUtil {

    private XmlUtil() {
    }

    /** SINK (CWE-611): factory created with no secure-processing hardening. */
    public static String parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // No disabling of DOCTYPE / external entities -> XXE.
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(
                new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        return doc.getDocumentElement().getTextContent();
    }

    /** Control sample: hardened parser (should NOT be flagged). */
    public static String parseSafe(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(
                new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        return doc.getDocumentElement().getTextContent();
    }
}

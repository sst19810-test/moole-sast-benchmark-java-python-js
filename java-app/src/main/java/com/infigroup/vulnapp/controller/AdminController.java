package com.infigroup.vulnapp.controller;

import java.util.Hashtable;

import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.infigroup.vulnapp.service.CryptoService;

/**
 * Admin endpoints demonstrating LDAP injection, open redirect, and weak
 * token generation.
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    private final CryptoService cryptoService;

    public AdminController(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    /** SINK (CWE-90): user value concatenated into an LDAP search filter. */
    @GetMapping("/ldap")
    public String ldap(@RequestParam String user) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(DirContext.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(DirContext.PROVIDER_URL, "ldap://10.10.60.20:389");
        DirContext ctx = new InitialDirContext(env);

        String filter = "(uid=" + user + ")";
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> results =
                ctx.search("ou=people,dc=example,dc=com", filter, sc);
        StringBuilder sb = new StringBuilder();
        while (results.hasMore()) {
            sb.append(results.next().getNameInNamespace()).append('\n');
        }
        return sb.toString();
    }

    /** CWE-330: token endpoint backed by java.util.Random. */
    @GetMapping("/token")
    public String token() {
        return cryptoService.generateToken();
    }
}

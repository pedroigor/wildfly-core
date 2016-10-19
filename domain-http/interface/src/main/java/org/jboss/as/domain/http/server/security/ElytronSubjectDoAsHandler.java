/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.as.domain.http.server.security;

import static org.wildfly.common.Assert.checkNotNullParam;


import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Set;
import java.util.stream.StreamSupport;

import javax.security.auth.Subject;


import org.jboss.as.controller.AccessAuditContext;
import org.jboss.as.core.security.RealmGroup;
import org.jboss.as.core.security.RealmRole;
import org.jboss.as.core.security.RealmUser;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;


import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;

/**
 * This is a temporary {@link HttpHandler} to convert from the Elytron {@link SecurityIdentity} to the {@link Subject}
 * representation currently in use within domain management.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@Deprecated
public class ElytronSubjectDoAsHandler extends SubjectDoAsHandler {

    private final SecurityDomain securityDomain;
    private final HttpHandler wrapped;

    public ElytronSubjectDoAsHandler(HttpHandler next, SecurityDomain securityDomain) {
        super(checkNotNullParam("next", next));
        this.wrapped = next;
        this.securityDomain = checkNotNullParam("securityDomain", securityDomain);
    }

    /**
     *
     * @see io.undertow.server.HttpHandler#handleRequest(io.undertow.server.HttpServerExchange)
     */
    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        Subject subject = new Subject();

        SecurityIdentity securityIdentity = securityDomain.getCurrentSecurityIdentity();
        if (securityIdentity != null) {
            Set<Principal> principals = subject.getPrincipals();
            principals.add(new RealmUser(securityIdentity.getPrincipal().getName()));

            StreamSupport.stream(securityIdentity.getRoles().spliterator(), true).forEach((String role) -> {
                principals.add(new RealmGroup(role));
                principals.add(new RealmRole(role));
            });
        }
        try {
            // TODO Elytron I expect this now to be broken.
            AccessAuditContext.doAs(securityIdentity, new PrivilegedExceptionAction<Void>() {

                @Override
                public Void run() throws Exception {
                    wrapped.handleRequest(exchange);
                    return null;
                }

            });
        } catch (PrivilegedActionException e) {
            throw e.getException();
        }
    }

}

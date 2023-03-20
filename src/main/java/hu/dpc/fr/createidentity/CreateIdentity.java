/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 *
 * Portions Copyright 2023 DPC Consulting Kft
 *
 */


package hu.dpc.fr.createidentity;


import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.security.AdminTokenAction;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.security.AccessController;
import java.util.*;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/**
 * A node that creates a new identity in IdRepo with a generated UUID userid.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = CreateIdentity.Config.class)
public class CreateIdentity extends SingleOutcomeNode {

    private final Logger logger = LoggerFactory.getLogger(CreateIdentity.class);
    private final Config config;
    private final Realm realm;
    private final static String HU_DPC_BX_sn = "bx-sn";
    private final static String HU_DPC_BX_givenName = "bx-givenName";

    /**
     * Configuration for the node.
     */
    public interface Config {
   
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm  The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public CreateIdentity  (@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        if (context.getStateFor(this).get(USERNAME) != null) {
            logger.warn("CREATEIDENTITY: there's already a USERNAME in shared state. will be overwritten");
        }

        String userId = UUID.randomUUID().toString();
        Map<String, Set<String>> userAttributes = new HashMap<>();
        userAttributes.put("_id", Collections.singleton(userId));
        userAttributes.put("username", Collections.singleton(userId));
        userAttributes.put("userpassword", Collections.singleton(userId)); // TODO WARNING REMOVE THIS

        if (context.getStateFor(this).get(HU_DPC_BX_sn) != null) {
            logger.info("CREATEIDENTITY: sn found in shared state, adding to user");
            userAttributes.put("sn", Collections.singleton(context.getStateFor(this).get(HU_DPC_BX_sn).asString()));
        }
        if (context.getStateFor(this).get(HU_DPC_BX_givenName) != null) {
            logger.info("CREATEIDENTITY: givenName found in shared state, adding to user");
            userAttributes.put("givenName", Collections.singleton(context.getStateFor(this).get(HU_DPC_BX_givenName).asString()));
        }

        logger.info("CREATEIDENTITY: userAttributes: " + userAttributes);

        try {
            AMIdentityRepository idRepo = getIdRepo(realm);
            AMIdentity userIdentity = idRepo.createIdentity(IdType.USER, userId, userAttributes);
            logger.info("CREATEIDENTITY: userIdentity created in repo: " + userIdentity);
        } catch (IdRepoException|SSOException e) {
            logger.error("CREATEIDENTITY: " + e.getMessage(), e);
            throw new NodeProcessException(e);
        }
        context.getStateFor(this).putShared(USERNAME, userId);
        logger.info("CREATEIDENTITY: added USERNAME in shared state: " + context.getStateFor(this).get(USERNAME).toString());

        return goToNext().build();
    }


    /**
     * Obtains an instance of AMIdentityRepository for the given realm.
     *
     * @throws IdRepoException If there are repository related error conditions
     * @throws SSOException If the admin's single sign on token is invalid.
     */
    public AMIdentityRepository getIdRepo(Realm realm) throws IdRepoException, SSOException{
        SSOToken adminToken = AccessController.doPrivileged(AdminTokenAction.getInstance());
        AMIdentityRepository identityRepository = new AMIdentityRepository(realm.asPath(), adminToken);
        logger.info("CREATEIDENTITY: id repo: " + identityRepository);
        return identityRepository;

    }

}

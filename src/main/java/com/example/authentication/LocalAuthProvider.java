package com.example.authentication;

import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.*;
import io.reactivex.rxjava3.core.BackpressureStrategy;
import io.reactivex.rxjava3.core.Flowable;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;

import java.util.Collections;

@Requires(property="identity-store")
@Singleton
@Primary
public class LocalAuthProvider implements AuthenticationProvider {

    private static final Logger log = org.slf4j.LoggerFactory.getLogger(LocalAuthProvider.class);
    private static final String CRED_NOT_VALID = "Invalid credentials";

    @Inject
    IdentityStore store;


    @Override
    public Publisher<AuthenticationResponse> authenticate(HttpRequest httpRequest, AuthenticationRequest authenticationRequest) {

        log.debug("start LocalAuthProvider.authenticate");

        return Flowable.create(emitter -> {

            String username = (String) authenticationRequest.getIdentity();
            String password = (String) authenticationRequest.getSecret();

            log.debug("authenticate user: "+username+" pass: "+password);

            if (password.equals(store.getUserPassword(username))) {

                emitter.onNext(AuthenticationResponse.success(username, Collections.singletonList(store.getUserRole(username))));
                emitter.onComplete();
                return;
            } else {
                emitter.onError(new AuthenticationException(new AuthenticationFailed(CRED_NOT_VALID)));
            }
            emitter.onComplete();
            return;

        }, BackpressureStrategy.ERROR);    }
}




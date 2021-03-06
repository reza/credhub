package org.cloudfoundry.credhub.services;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.constants.EncryptionConstants;

@Service
@Profile("!unit-test")
public class DefaultPasswordKeyProxyFactory implements PasswordKeyProxyFactory {
  @Override
  public KeyProxy createPasswordKeyProxy(
    final EncryptionKeyMetadata encryptionKeyMetadata, final InternalEncryptionService encryptionService) {
    return new PasswordBasedKeyProxy(encryptionKeyMetadata.getEncryptionPassword(), EncryptionConstants.ITERATIONS, encryptionService);
  }
}

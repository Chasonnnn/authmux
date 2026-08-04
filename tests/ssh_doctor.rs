use authmux::{
    DoctorOutcome, ExecutionSelection, ProbeOutput, ProbePolicy, ProbeRunner, ProviderFailure,
    SshDoctor, UserConfig,
};

struct SshDoctorFixture {
    output: ProbeOutput,
}

impl ProbeRunner for SshDoctorFixture {
    fn probe(
        &self,
        command: &authmux::CommandSpec,
        selection: &ExecutionSelection,
        _policy: ProbePolicy,
    ) -> Result<ProbeOutput, ProviderFailure> {
        assert_eq!(command.program(), "ssh");
        assert_eq!(command.arguments(), ["-V"]);
        assert!(selection.environment().is_empty());
        Ok(self.output.clone())
    }
}

#[test]
fn ssh_doctor_reports_local_readiness_and_remote_uncertainty_separately() {
    let definition = ssh_definition();
    let ssh = definition.ssh().expect("SSH Provider Profile resolves");
    let result = SshDoctor::new(SshDoctorFixture {
        output: ProbeOutput::exited(0, b"", b"OpenSSH_10.2p1, LibreSSL 3.3.6\n"),
    })
    .diagnose(definition.name(), ssh);

    assert_eq!(result.context(), "empire");
    assert_eq!(result.outcome(), DoctorOutcome::Warning);
    assert!(!result.provider_contacted());
    assert!(result.checks().iter().any(|check| {
        check.id() == "openssh_client"
            && check.outcome() == DoctorOutcome::Pass
            && check.summary() == "OpenSSH_10.2p1 is supported"
    }));
    assert!(result.checks().iter().any(|check| {
        check.id() == "ssh_remote_session"
            && check.outcome() == DoctorOutcome::Warning
            && check.summary()
                == "remote identity, authorization, MFA state, Session Usability, and expiry were not observed"
    }));
}

#[test]
fn ssh_doctor_failure_does_not_expose_native_output() {
    let seeded_output = "fictional-sensitive-native-error";
    let definition = ssh_definition();
    let result = SshDoctor::new(SshDoctorFixture {
        output: ProbeOutput::exited(255, b"", seeded_output.as_bytes()),
    })
    .diagnose(
        definition.name(),
        definition.ssh().expect("SSH Provider Profile resolves"),
    );
    let diagnostic = format!("{result:?}");

    assert_eq!(result.outcome(), DoctorOutcome::Fail);
    assert!(result.checks().iter().any(|check| {
        check.id() == "openssh_client"
            && check.outcome() == DoctorOutcome::Fail
            && check.summary() == "OpenSSH client readiness could not be established"
    }));
    assert!(!diagnostic.contains(seeded_output));
}

fn ssh_definition() -> authmux::ContextDefinition {
    let config = UserConfig::parse(
        "version = 1\n\
         [contexts.empire.providers.ssh]\n\
         host_alias = \"empire-alpha\"\n\
         expected_remote_principal = \"researcher@example.invalid\"\n",
    )
    .expect("fictional SSH context is valid");
    config
        .resolve_context_definition("empire")
        .expect("fictional SSH context resolves")
}

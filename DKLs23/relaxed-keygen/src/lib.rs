//! Simple protocol in which parties cooperate to generate randomness

#![no_std]
#![forbid(unused_crate_dependencies, missing_docs)]

#[cfg(test)]
extern crate std;

extern crate alloc;

mod _unused_deps {
    // We don't use it directly, but we need to enable `serde` feature
    use generic_array as _;
}

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};
use sha2::{Sha256, digest::Output};

use round_based::{
    PartyIndex,
    mpc::{Mpc, MpcExecution},
};

use generic_ec::{Curve, Point, Scalar, SecretScalar};
use generic_ec_zkp::polynomial::Polynomial;

/// Protocol message
#[derive(round_based::ProtocolMsg, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Msg<E: Curve> {
    /// Round 1 broadcast: commitment to the vector of curve points
    CommitPoints(CommitPointsMsg),
    /// Round 1 pairwise: commitment to a receiver's subshare
    CommitSubshare(CommitSubshareMsg),
    /// Round 2: echo broadcast commitments
    EchoDigest(EchoDigestMsg),
    /// Round 2 broadcast: decommit the vector of curve points
    DecommitPoints(DecommitPointsMsg<E>),
    /// Round 2 pairwise: decommit a receiver's subshare
    DecommitSubshare(DecommitSubshareMsg<E>),
    /// Round 3 verify
    Verify(VerifyMsg),
}

/// Message from round 1
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "udigest", derive(udigest::Digestable))]
pub struct CommitPointsMsg {
    /// Party commitment
    #[cfg_attr(feature = "udigest", udigest(as_bytes))]
    pub commitment: Output<Sha256>,
    sid: u64,
}

/// Pairwise commitment message from round 1
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "udigest", derive(udigest::Digestable))]
pub struct CommitSubshareMsg {
    /// Party commitment
    #[cfg_attr(feature = "udigest", udigest(as_bytes))]
    pub commitment: Output<Sha256>,
    sid: u64,
}

/// Echo broadcast commitments message from round 2
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "udigest", derive(udigest::Digestable))]
pub struct EchoDigestMsg {
    /// Party commitments as digest
    #[cfg_attr(feature = "udigest", udigest(as_bytes))]
    pub digest: Output<Sha256>,
    sid: u64,
}

/// Round 2 broadcast: opening of the curve-points commitment.
///
/// Carries the values needed to recompute the [`CommittedPoints`] digest; the
/// remaining context (committer index, sid) is known to the verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DecommitPointsMsg<E: Curve> {
    /// The committed vector of curve points
    pub points: Vec<Point<E>>,
    /// Commitment nonce
    nonce: [u8; NONCE_BYTES],
}

/// Round 2 pairwise: opening of a subshare commitment.
///
/// Carries the values needed to recompute the [`CommittedSubshare`] digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DecommitSubshareMsg<E: Curve> {
    /// The committed subshare
    pub subshare: Scalar<E>,
    /// Commitment nonce
    nonce: [u8; NONCE_BYTES],
}

/// Round 3 verify
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyMsg {
    sid: u64,
    ok: bool,
}

const LAMBDA_BITS: usize = 128;
const NONCE_BYTES: usize = 2 * LAMBDA_BITS / 8;

#[derive(udigest::Digestable)]
#[udigest(tag = "dkls23.keygen.committed_points")]
#[udigest(bound = "")] // surrpress derive's default E: Digestable bound for E: Curve
struct CommittedPoints<'a, E: Curve> {
    committer: PartyIndex,
    sid: u64,
    points: &'a [Point<E>],
    #[udigest(as_bytes)]
    nonce: [u8; NONCE_BYTES],
}

#[derive(udigest::Digestable)]
#[udigest(tag = "dkls23.keygen.committed_subshare")]
#[udigest(bound = "")] // surrpress derive's default E: Digestable bound for E: Curve
struct CommittedSubshare<E: Curve> {
    committer: PartyIndex,
    receiver: PartyIndex,
    sid: u64,
    subshare: Scalar<E>,
    #[udigest(as_bytes)]
    nonce: [u8; NONCE_BYTES],
}

#[derive(udigest::Digestable)]
#[udigest(tag = "dkls23.keygen.echo_commitments")]
struct EchoCommitments<'a> {
    sid: u64,
    #[udigest(as = &[udigest::Bytes])]
    commitments: &'a [Output<Sha256>],
}

enum Verification<E: Curve> {
    Abort,
    Success(KeyPair<E>),
}

/// Keypair output from the protocol
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct KeyPair<E: Curve> {
    sid: u64,
    share_point_0: Point<E>,
    share_i: Scalar<E>,
}

/// Carries out the key generation protocol
pub async fn relaxed_key_generation<R, M, E>(
    mut mpc: M,
    i: PartyIndex, // Party 1, 2, ..., n
    n: PartyIndex,
    t: PartyIndex,
    sid: u64,
    mut rng: R,
) -> Result<KeyPair<E>, ErrorM<M>>
where
    M: Mpc<Msg = Msg<E>>,
    R: rand_core::RngCore,
    E: generic_ec::Curve,
{
    // This party's routing index used by `round-based`.
    // `round-based` indexes parties by a 0-based routing index in `[0, n)`,
    // while the protocol math uses 1-based party labels `[1, n]`. 
    // We convert at every `round-based` boundary (round setup, `send_p2p` receiver, etc) to use
    // 0-based `me`, and keep the polynomial math in 1-based `i`.
    let me = i - 1;

    // Define rounds
    let round1_commit_points = mpc.add_round(round_based::round::broadcast::<CommitPointsMsg>(me, n));
    let round1_commit_subshares = mpc.add_round(round_based::round::p2p::<CommitSubshareMsg>(me, n));
    let round2_echo_digest = mpc.add_round(round_based::round::broadcast::<EchoDigestMsg>(me, n));
    let round2_decommit_points = mpc.add_round(round_based::round::broadcast::<DecommitPointsMsg<E>>(me, n));
    let round2_decommit_subshares = mpc.add_round(round_based::round::p2p::<DecommitSubshareMsg<E>>(me, n));
    let round3_verify = mpc.add_round(round_based::round::broadcast::<VerifyMsg>(me, n));

    let mut mpc = mpc.finish_setup();

    // --- The Protocol ---

    // 1. Generate local randomness
    let p_i = Polynomial::<SecretScalar<E>>::sample(&mut rng, usize::from(t) - 1);
    // n subshares p_i(j) for j = 1, 2, ..., n
    let subshares: Vec<Scalar<E>> = (1..=n).map(|j| 
        p_i.value::<_, Scalar<E>>(&Scalar::<E>::from(j))
    ).collect();
    // t points P_i(j) for j = 0, 1, ..., t - 1
    let subshare_curve_points: Vec<Point<E>> = (0..t).map(|j|
        p_i.value::<_, Scalar<E>>(&Scalar::<E>::from(j)) * Point::<E>::generator()
    ).collect();

    let mut nonce = [0u8; NONCE_BYTES];
    rng.fill_bytes(&mut nonce);
    let committed_points = CommittedPoints { 
        committer: i, 
        sid: sid, 
        points: &subshare_curve_points, 
        nonce: nonce 
    };
    let points_commitment = udigest::hash::<Sha256>(&committed_points);

    // Broadcast commitment to the vector of curve points.
    mpc.send_to_all(Msg::CommitPoints(CommitPointsMsg {
        commitment: points_commitment,
        sid: sid,
    }))
    .await
    .map_err(Error::Round1Send)?;

    // Pairwise commitment to each receiver's subshare.
    let receivers: Vec<PartyIndex> = (1..=n).filter(|&j| j != i).collect();
    let committed_subshares: Vec<CommittedSubshare<E>> = receivers.iter().map(|&j| CommittedSubshare {
        committer: i,
        receiver: j,
        sid: sid,
        subshare: subshares[j as usize - 1],
        nonce: {
            let mut nonce = [0u8; NONCE_BYTES];
            rng.fill_bytes(&mut nonce);
            nonce
        },
    }).collect();

    for committed_subshare in &committed_subshares {
        // `receiver` is 1-based label; `send_p2p` uses 0-based routing index.
        mpc.send_p2p(committed_subshare.receiver - 1, Msg::CommitSubshare(CommitSubshareMsg {
            commitment: udigest::hash::<Sha256>(committed_subshare),
            sid: sid,
        }))
        .await
        .map_err(Error::Round1Send)?;
    }

    let received_points_commitments = mpc
        .complete(round1_commit_points)
        .await
        .map_err(Error::Round1Receive)?;
    let received_subshare_commitments = mpc
        .complete(round1_commit_subshares)
        .await
        .map_err(Error::Round1Receive)?;

    // 2. decomit
    // Echo for broadcast points commitments
    let other_points_commitments: Vec<Output<Sha256>> =
        received_points_commitments.iter().map(|c| c.commitment).collect();
    // Rebuild the full n-length commitment vector in absolute party order for the echo digest. 
    let all_points_commitments = [&other_points_commitments[0..me as usize], &[points_commitment], &other_points_commitments[me as usize..]].concat();

    let echo_digest = udigest::hash::<Sha256>(&EchoCommitments {
        sid: sid,
        commitments: &all_points_commitments,
    });
    mpc.send_to_all(Msg::EchoDigest(EchoDigestMsg {
        digest: echo_digest,
        sid: sid,
    }))
    .await
    .map_err(Error::Round2Send)?;
    
    // Open for points and subshare commitments
    mpc.send_to_all(Msg::DecommitPoints(DecommitPointsMsg {
        points: subshare_curve_points.clone(),
        nonce,
    }))
    .await
    .map_err(Error::Round2Send)?;

    for committed_subshare in &committed_subshares {
        mpc.send_p2p(
            // 1-based `receiver` label -> 0-based routing index.
            committed_subshare.receiver - 1,
            Msg::DecommitSubshare(DecommitSubshareMsg {
                subshare: committed_subshare.subshare,
                nonce: committed_subshare.nonce,
            }),
        )
        .await
        .map_err(Error::Round2Send)?;
    }

    let received_echo_digests = mpc.complete(round2_echo_digest).await.map_err(Error::Round2Receive)?;
    let received_decommit_points = mpc.complete(round2_decommit_points).await.map_err(Error::Round2Receive)?;
    let received_decommit_subshares = mpc.complete(round2_decommit_subshares).await.map_err(Error::Round2Receive)?;

    // 3. Verify
    // Echo agreement
    let verification = if received_echo_digests.iter().any(|m| m.digest != echo_digest) {
        // Send abort
        let verify = VerifyMsg { sid: sid, ok: false };
        mpc.send_to_all(Msg::Verify(verify)).await.map_err(Error::Round3Send)?;
        // Go to output
        Verification::Abort
    } else if received_decommit_points.iter_indexed().zip(received_points_commitments.iter_indexed()).any(|((j, _, d), (_, _, c))| {
        let committed_points = CommittedPoints {
            // Convert 0-based sender routing index to committer's 1-based label
            committer: j + 1,
            sid: sid,
            points: &d.points,
            nonce: d.nonce,
        };
        c.commitment != udigest::hash::<Sha256>(&committed_points)
    }) {
        // Send abort
        let verify = VerifyMsg { sid: sid, ok: false };
        mpc.send_to_all(Msg::Verify(verify)).await.map_err(Error::Round3Send)?;
        // Go to output
        Verification::Abort
    } else if received_decommit_subshares.iter_indexed().zip(received_subshare_commitments.iter_indexed()).any(|((j, _, d), (_, _, c))| {
        let committed_subshare = CommittedSubshare {
            // Convert 0-based sender routing index to committer's 1-based label
            committer: j + 1,
            receiver: i,
            sid: sid,
            subshare: d.subshare,
            nonce: d.nonce,
        };
        c.commitment != udigest::hash::<Sha256>(&committed_subshare)
    }) {
        // Send abort
        let verify = VerifyMsg { sid: sid, ok: false };
        mpc.send_to_all(Msg::Verify(verify)).await.map_err(Error::Round3Send)?;
        // Go to output
        Verification::Abort
    } else {
        // Verify expected share curve point
        let share_points: Vec<Point<E>> = (0..t).map(|k| 
            received_decommit_points.iter().map(|p| p.points[k as usize]).sum::<Point<E>>() + subshare_curve_points[k as usize]).collect();
        let share: Scalar<E> = received_decommit_subshares.iter().map(|s| s.subshare).sum::<Scalar<E>>() + subshares[i as usize - 1];
        let share_curve_point = share * Point::<E>::generator();

        // Expected share curve point
        let expected_share_curve_point: Point<E> = if i <= t - 1 {
            share_points[i as usize]
        } else {
            // Build from lagrange t curve points
            let index_set: Vec<Scalar<E>> = (1..=t - 1).chain([i]).map(|k| Scalar::<E>::from(k)).collect();
            let l_i_inv = lo(&index_set, i)?
                .invert()
                .ok_or(InternalErr::ArithmeticError("l_i invert".into()))?;
            let mut acc = lo(&index_set, 1)? * share_points[1];
            for k in 2..=t-1 {
                acc += lo(&index_set, k)? * share_points[k as usize];
            }
            l_i_inv * (share_points[0] - acc)
        };

        if share_curve_point != expected_share_curve_point {
            // Send abort
            let verify = VerifyMsg { sid: sid, ok: false };
            mpc.send_to_all(Msg::Verify(verify)).await.map_err(Error::Round3Send)?;
            // Go to output
            Verification::Abort
        } else {
            // Send ok
            let verify = VerifyMsg { sid: sid, ok: true };
            mpc.send_to_all(Msg::Verify(verify)).await.map_err(Error::Round3Send)?;
            // Go to output
            Verification::Success(KeyPair { sid, share_point_0: share_points[0], share_i: share })
        }
    };

    let received_verifications = mpc.complete(round3_verify).await.map_err(Error::Round3Receive)?;

    // Output
    if received_verifications.iter().any(|v| !v.ok) {
        Err(Error::Abort { sid })
    } else {
        match verification {
            Verification::Abort => Err(Error::Abort { sid }),
            Verification::Success(keypair) => Ok(keypair),
        }
    }
}

fn lo<E: Curve>(s: &[Scalar<E>], k: PartyIndex) -> Result<Scalar<E>, InternalErr> {
    let k = Scalar::<E>::from(k);
    lagrange(s, k, Scalar::<E>::zero())
}

fn lagrange<E: Curve>(s: &[Scalar<E>], k: Scalar<E>, x: Scalar<E>) -> Result<Scalar<E>, InternalErr> {
    let mut prod = Scalar::<E>::one();
    for &l in s {
        if l != k {
            prod *= (x - l) * (k - l).invert().ok_or(InternalErr::ArithmeticError("lagrange invert".into()))?;
        }
    }
    Ok(prod)
}

/// Internal error
#[derive(Debug, thiserror::Error)]
pub enum InternalErr {
    /// Arithmetic error
    #[error("arithmetic error at: {0}")]
    ArithmeticError(String),
}


/// Protocol error
#[derive(Debug, thiserror::Error)]
pub enum Error<RecvErr, SendErr, InternalErr> {
    /// Couldn't send a message in the first round
    #[error("send a message at round 1")]
    Round1Send(#[source] SendErr),
    /// Couldn't receive a message in the first round
    #[error("receive messages at round 1")]
    Round1Receive(#[source] RecvErr),
    /// Couldn't send a message in the second round
    #[error("send a message at round 2")]
    Round2Send(#[source] SendErr),
    /// Couldn't receive a message in the second round
    #[error("receive messages at round 2")]
    Round2Receive(#[source] RecvErr),
    /// Couldn't send a message in the third round
    #[error("send a message at round 3")]
    Round3Send(#[source] SendErr),
    /// Couldn't receive a message in the third round
    #[error("receive messages at round 3")]
    Round3Receive(#[source] RecvErr),

    /// Internal error
    #[error("Internal error")]
    InternalError(#[source] InternalErr),

    /// The protocol was aborted because a check failed (e.g. a decommitment
    /// didn't match its commitment, or the echo consistency check failed). The
    /// message carries context such as the offending party index.
    #[error("protocol aborted: {sid:?}")]
    Abort {
        /// Session id of the aborted protocol run
        sid: u64,
    },
}

/// Error type deduced from `M: Mpc`
pub type ErrorM<M> = Error<
    round_based::mpc::CompleteRoundErr<M, round_based::round::RoundInputError>,
    <M as Mpc>::SendErr,
    InternalErr,
>;

impl<RecvErr, SendErr> From<InternalErr> for Error<RecvErr, SendErr, InternalErr> {
    fn from(e: InternalErr) -> Self {
        Error::InternalError(e)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use generic_ec::{Curve, Point, Scalar, curves::Secp256k1};
    use generic_ec_zkp::polynomial::lagrange_coefficient;
    use rand::seq::SliceRandom;

    use super::{KeyPair, relaxed_key_generation};

    const SID: u64 = 1;

    /// Covers 
    /// - the direct branch (party labels `<= t-1`), 
    /// - the Lagrange branch (labels `>= t`), 
    /// - the full-threshold `t = n`
    const CASES: &[(u16, u16)] = &[(2, 2), (2, 3), (3, 3), (3, 5), (5, 5)];

    /// Interpolates the secret-sharing polynomial through `polynomial_points` evaluated at `x`,
    /// where x is not an coordinate of one of the points.
    /// The `polynomial_points` are (1-based label, share) pairs.
    fn interpolate_at<E: Curve>(polynomial_points: &[(u16, Scalar<E>)], x: Scalar<E>) -> Scalar<E> {
        let xs: Vec<Scalar<E>> = polynomial_points.iter().map(|(label, _)| Scalar::from(*label)).collect();
        polynomial_points.iter()
            .enumerate().map(|(j, (_, share))| {
                lagrange_coefficient(x, j, &xs).expect("x is not part of one of the polynomial points") * *share
            })
            .sum::<Scalar<E>>()
    }

    /// Validates a threshold keygen output:
    /// - every party agrees on the shared public key `P(0)` and the session id
    /// - all `n` shares lie on one degree-`(t-1)` polynomial.
    fn validate<E: Curve>(t: u16, n: u16, key_shares: &[KeyPair<E>], rng: &mut impl rand::RngCore) {
        assert_eq!(key_shares.len(), usize::from(n));

        let public_key = key_shares[0].share_point_0;
        for share in key_shares {
            assert_eq!(share.sid, SID);
            assert_eq!(share.share_point_0, public_key);
        }

        // The party at 0-based position `k` holds the share at evaluation point `k + 1` (the 1-based party label).
        let all: Vec<(u16, Scalar<E>)> =
            (1..=n).zip(key_shares.iter().map(|ks| ks.share_i)).collect();
        let subset: Vec<(u16, Scalar<E>)> =
            all.choose_multiple(rng, usize::from(t)).copied().collect();

        // The polynomial through the random `t`-subset must reproduce every other party's share
        for (label, share) in &all {
            if subset.iter().any(|(l, _)| l == label) {
                continue;
            }
            assert_eq!(interpolate_at(&subset, Scalar::from(*label)), *share);
        }

        // Constant term `p(0)` is the secret behind the public key.
        let secret = interpolate_at(&subset, Scalar::zero());
        assert_eq!(secret * Point::<E>::generator(), public_key);
    }

    fn keygen_works(t: u16, n: u16) {
        let mut rng = rand_dev::DevRng::new();

        let key_shares = round_based::sim::run_with_setup(
            core::iter::repeat_with(|| rng.fork()).take(n.into()),
            // `round-based` uses 0-based party indexes; the protocol uses 1-based.
            |i, party, rng| relaxed_key_generation::<_, _, Secp256k1>(party, i + 1, n, t, SID, rng),
        )
        .unwrap()
        .expect_ok()
        .into_vec();

        validate(t, n, &key_shares, &mut rng);
    }

    #[test]
    fn simulation() {
        for &(t, n) in CASES {
            keygen_works(t, n);
        }
    }

    #[tokio::test]
    async fn simulation_async() {
        let (t, n) = (3, 5);
        let mut rng = rand_dev::DevRng::new();

        let key_shares = round_based::sim::async_env::run_with_setup(
            core::iter::repeat_with(|| rng.fork()).take(n.into()),
            |i, party, rng| relaxed_key_generation::<_, _, Secp256k1>(party, i + 1, n, t, SID, rng),
        )
        .await
        .expect_ok()
        .into_vec();

        validate(t, n, &key_shares, &mut rng);
    }
}

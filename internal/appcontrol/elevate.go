package appcontrol

// Application elevation: letting a standard user run ONE named application
// with administrator rights, while everything else they launch stays
// unprivileged.
//
// This is the opposite direction of travel to the rest of this package. Every
// other mechanism here takes something away — closes a process, withholds an
// execute bit, moves an application aside — and the worst outcome of getting
// one wrong is software that does not run. Elevation GIVES something away, and
// the worst outcome of getting it wrong is that any local user on the machine
// becomes an administrator, using a feature this product installed for them.
//
// So the rules are stricter than for blocking, and they are rules rather than
// preferences:
//
//   - Only a RULE may elevate. The policy's default action cannot: the backend
//     already forces a default of allow or block, and nothing here may widen
//     that, because a default of elevate means "run everything as admin".
//   - Audit mode elevates nothing, exactly as it blocks nothing.
//   - A block always beats an elevate for the same application. Refusing to run
//     something is a safe mistake; running it as administrator is not.
//   - Protected system paths and the agent's own binaries are never elevated.
//   - Every grant is recorded and withdrawn on policy change and on uninstall,
//     through the same state file as locks — an elevation left behind after
//     the policy stopped asking for it is a permanent hole.
//
// The platform mechanism itself is deliberately behind an interface, because
// the two platforms differ so much that sharing code between them would mean
// pretending they do the same thing.

// Elevator grants and withdraws the ability to run one application elevated.
//
// Allow must be idempotent: it is called on every reconcile pass for as long as
// the rule stands. Revoke must undo exactly what Allow did, because what is
// left behind is a way for a user to run something as administrator that
// nobody has asked for any more.
type Elevator interface {
	// Kind names the mechanism, for the activity trail. An operator deciding
	// whether to rely on this needs to know HOW it is done — the two platforms
	// give materially different guarantees.
	Kind() string

	// Supported reports whether this platform can elevate at all. When it
	// cannot, a rule asking for elevation is reported as unsupported rather
	// than silently doing nothing, which is the failure mode this product has
	// already been bitten by more than once.
	Supported() bool

	Allow(t Target) error
	Revoke(t Target) error
}

// Elevation mechanisms, reported with each event.
const (
	// MechanismElevate: an application was granted the right to run elevated.
	MechanismElevate = "elevate"
	// MechanismElevateRevoked: that grant was withdrawn.
	MechanismElevateRevoked = "elevate-revoked"
	// MechanismElevateLaunch: an application actually ran elevated. This is
	// the line an auditor cares about — the others describe configuration,
	// this one describes something that happened.
	MechanismElevateLaunch = "elevate-launch"
)

// maxElevatedPerPass is the blast-radius ceiling for elevation.
//
// Far lower than the one for blocking, and deliberately so. Blocking fifty
// applications is a plausible thing for an allow-list policy to want; elevating
// fifty is not a policy anybody writes on purpose, it is a rule that matched
// more than its author meant — and the result is a machine where most software
// runs as administrator. Past this the pass is refused whole and reported.
const maxElevatedPerPass = 10

// unsupportedElevator is used on platforms with no mechanism.
//
// It says so rather than silently succeeding. A rule that cannot be honoured
// has to surface as an unsupported rule in the portal, because "the policy
// says elevate and nothing happens" is indistinguishable from the product
// being broken — which is exactly how the publisher bug and the elevate no-op
// stayed hidden for as long as they did.
type unsupportedElevator struct{ reason string }

func (u unsupportedElevator) Kind() string    { return "unsupported" }
func (u unsupportedElevator) Supported() bool { return false }

func (u unsupportedElevator) Allow(Target) error  { return errUnsupported{u.reason} }
func (u unsupportedElevator) Revoke(Target) error { return nil }

type errUnsupported struct{ reason string }

func (e errUnsupported) Error() string { return e.reason }

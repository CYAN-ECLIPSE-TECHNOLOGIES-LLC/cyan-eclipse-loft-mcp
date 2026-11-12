#!/usr/bin/env python3
# Eclipse Loft MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Loft MCP server — 11 typed tools, stdio JSON-RPC (Strata §8).

"""Eclipse Loft — governed design-to-print authority for agents.
Descriptor: governed design-to-print authority for agents — signed provenance
from model to machine, safety envelopes at the bridge, evidence for every print.
Transport: MCP over stdio, stdlib only. P0: simulators only.
Powered by Cyan Eclipse Technologies — https://cetech.ai
"""
import json, os, sys
from pathlib import Path
HERE = Path(__file__).parent; sys.path.insert(0, str(HERE))
import strata_engine as eng
from strata_engine import Engine, Refusal
from guards import ToolError, err32602, require_str, require_dict

ENGINE = Engine(Path(os.environ.get("ECLIPSE_STRATA_DIR", HERE)))
TOOLS = ["design_register","design_inspect","design_pin_get","printers_discover","session_open","job_prepare",
         "job_dispatch","job_status","job_abort","telemetry_read","session_close"]
DESCRIPTOR = "governed design-to-print authority for agents — signed provenance from model to machine, safety envelopes at the bridge, evidence for every print."
FORBIDDEN = {}
for n in ("raw_gcode","send_gcode","printer_command","gcode_script","execute_code","execute_blender_code","move_axis","set_heater","set_fan","heat_hotend"):
    FORBIDDEN[n] = "RAW_GCODE_REFUSED"
for n in ("config_write","firmware_update","set_max_temp","eeprom_save","write_config"):
    FORBIDDEN[n] = "CONFIG_WRITE_REFUSED"
FORBIDDEN["design_pin_activate"] = "AGENT_SELF_PIN_REFUSED"
FORBIDDEN["profile_pin_activate"] = "AGENT_SELF_PIN_REFUSED"

def _p(a, name):
    if name not in a: raise err32602(name, "ARG_REQUIRED")
    return a[name]

def call_tool(name, args):
    if name in FORBIDDEN:
        ENGINE.receipt(name, FORBIDDEN[name], "forbidden_name_on_surface")
        raise ToolError(-32602, refusal=FORBIDDEN[name], arg=name)
    if name not in TOOLS:
        raise ToolError(-32602, refusal="UNKNOWN_TOOL", arg=name)
    a = args or {}
    if not isinstance(a, dict): raise err32602("arguments")
    try:
        if name == "design_register":
            prof = a.get("profile")
            out = ENGINE.design_register(require_str(a.get("agent_identity"), "agent_identity") if a.get("agent_identity") else "agent-anon",
                                         _p(a, "source"), _p(a, "parameter_set"), a.get("source_kind", "code_first"))
            if prof is not None: out["profile_proposal"] = ENGINE.register_profile(a.get("agent_identity","agent"), prof)
            if a.get("activate"): ENGINE.refuse(name, "AGENT_SELF_PIN_REFUSED", "activate_flag_in_register")
            return out
        if name == "design_inspect": return ENGINE.design_inspect(require_str(_p(a,"design_id"),"design_id"))
        if name == "design_pin_get": return ENGINE.design_pin_get(require_str(_p(a,"design_id"),"design_id"))
        if name == "printers_discover": return ENGINE.printers_discover()
        if name == "session_open": return ENGINE.session_open(require_dict(_p(a,"mandate"),"mandate"), require_str(_p(a,"agent_identity"),"agent_identity"))
        if name == "job_prepare": return ENGINE.job_prepare(require_str(_p(a,"session_id"),"session_id"), require_str(_p(a,"design_id"),"design_id"),
                                        require_str(_p(a,"profile_id"),"profile_id"), require_str(_p(a,"printer_serial"),"printer_serial"), a.get("supplied_toolpath"))
        if name == "job_dispatch": return ENGINE.job_dispatch(require_str(_p(a,"session_id"),"session_id"), require_str(_p(a,"job_hash"),"job_hash"),
                                        a.get("supplied_toolpath"), a.get("scheduled_at"))
        if name == "job_status": return ENGINE.job_status(require_str(_p(a,"session_id"),"session_id"), require_str(_p(a,"job_hash"),"job_hash"))
        if name == "job_abort": return ENGINE.job_abort(require_str(_p(a,"session_id"),"session_id"), require_str(_p(a,"job_hash"),"job_hash"))
        if name == "telemetry_read": return ENGINE.telemetry_read(require_str(_p(a,"session_id"),"session_id"), require_str(_p(a,"printer_serial"),"printer_serial"))
        if name == "session_close": return ENGINE.session_close(require_str(_p(a,"session_id"),"session_id"))
    except Refusal as r:
        return {"is_error": True, "refusal_code": r.code, "factor": r.factor}
    raise err32602(name)

def _ann(read_only, destructive=False, idempotent=False):
    return {"readOnlyHint": read_only, "destructiveHint": destructive,
            "idempotentHint": idempotent, "openWorldHint": False}

def _sp(d): return {"type": "string", "description": d}
def _op(d): return {"type": "object", "description": d}
def _ap(d, items=None):
    p = {"type": "array", "description": d}
    if items is not None: p["items"] = items
    return p
def _bp(d): return {"type": "boolean", "description": d}
def _np(d): return {"type": "number", "description": d}
def _out(props, required=None):
    s = {"type": "object", "properties": props}
    if required: s["required"] = required
    return s

_CTXT = ("Local stdio server, simulators only: the printers are "
         "virtual, no real printer is driven and no network is "
         "used; there is no rate limit and no credential beyond "
         "the signed mandates and pins the tools themselves "
         "check. Designs, profiles, sessions, and jobs live in "
         "server-process memory; only signer keys and the "
         "evidence packs sealed at session_close persist on "
         "disk. Refusals return either an error object "
         "{is_error, refusal_code, factor} or a JSON-RPC -32602 "
         "error naming the argument at fault. ")

_PIN = {"type": "object", "description": "Pin hashes: "
        "design_source_hash, parameter_set_hash, export_hash.",
        "properties": {
            "design_source_hash": _sp("SHA-256 of the design source."),
            "parameter_set_hash": _sp("SHA-256 of the canonical parameter set."),
            "export_hash": _sp("SHA-256 of the simulated export.")}}
_GEOM = {"geometry_basis": _sp("Always declared_geometry_only."),
         "inspection_basis": _sp("Always declared_geometry_only_no_kernel_inspection."),
         "bbox_mm": _op("Declared bounding box {x, y, z} in millimetres."),
         "volume_mm3": _np("Bounding-box volume computed from the declared box."),
         "min_wall_mm": _np("Declared minimum wall thickness."),
         "manifold": {"type": ["boolean", "null"], "description": "Always null: no mesh inspection is performed, so manifoldness is reported unchecked, never fabricated."},
         "triangle_count": {"type": ["integer", "null"], "description": "Always null: no mesh inspection is performed."},
         "face_count": {"type": ["integer", "null"], "description": "Always null: no mesh inspection is performed."}}

# name -> (description, input properties, required, annotations, outputSchema)
TOOL_DEFS = {}

TOOL_DEFS["design_register"] = (
    "Register a design source plus its parameter set and receive "
    "its content pin (source, parameter-set, and export hashes) "
    "in PROPOSED status. Use as the first step for any print "
    "work; use design_inspect to read a registered design's "
    "geometry and design_pin_get for its pin and activation "
    "state. Mutating: stores the design under a deterministic "
    "id derived from the source hash (re-registering the same "
    "source replaces its record as PROPOSED). A design cannot "
    "be printed until a human principal activates its pin "
    "outside this tool surface — agents cannot activate pins, "
    "and passing activate=true is refused with "
    "AGENT_SELF_PIN_REFUSED after the registration is recorded. "
    "Geometry is computed from the DECLARED parameter set only "
    "(bounding box and minimum wall): no mesh or kernel "
    "inspection is performed, and uninspectable facts are "
    "reported as null, never invented. An optional profile "
    "object is also registered as a profile proposal in the "
    "same call (flattened profiles get a profile_hash; profiles "
    "using inherits/include stay PROPOSED_UNRESOLVED and will "
    "refuse at job_prepare). " + _CTXT +
    "Returns {design_id, status, pin, geometry, note} plus "
    "profile_proposal when a profile was supplied.",
    {"agent_identity": _sp("Identity of the registering agent, "
                           "recorded as proposed_by; defaults to "
                           "'agent-anon'."),
     "source": _sp("Design source text (code-first model "
                   "source). Its SHA-256 forms the design_id "
                   "and the pin's design_source_hash."),
     "parameter_set": _op("Declared parameters object. "
                          "bbox_mm {x, y, z} (numbers, "
                          "millimetres; defaults to 20x20x10) "
                          "and min_wall_mm (number; defaults to "
                          "1.2) drive the reported geometry and "
                          "later slicing; malformed values "
                          "refuse by name."),
     "source_kind": _sp("How the source was produced; defaults "
                        "to 'code_first'."),
     "profile": _op("Optional slicer profile object to register "
                    "as a proposal in the same call: temps "
                    "{hotend, bed, first_layer_hotend, "
                    "first_layer_bed} and filament "
                    "{diameter_mm, density_g_cm3} are the fields "
                    "slicing later requires."),
     "activate": _bp("Must be absent or false: agents cannot "
                     "activate their own pins; a true value is "
                     "refused with AGENT_SELF_PIN_REFUSED.")},
    ["source", "parameter_set"], _ann(False),
    _out({"design_id": _sp("Deterministic id: 'design-' plus "
                           "the first 12 hex of the source hash."),
          "status": _sp("Always PROPOSED from this tool."),
          "pin": _PIN,
          "geometry": _op("Declared-geometry object (see "
                          "design_inspect)."),
          "note": _sp("States that activation requires a "
                      "human-principal signed pin record."),
          "profile_proposal": _op("Present only when profile "
                                  "was supplied: {profile_id, "
                                  "status, profile_hash or note}.")},
         ["design_id", "status", "pin"]))

TOOL_DEFS["design_inspect"] = (
    "Read a registered design's declared geometry: bounding "
    "box, bounding-box volume, and minimum wall thickness. Use "
    "to check a design's declared dimensions; use "
    "design_pin_get for the design's pin, status, and mandate "
    "bindings instead. Read-only. The geometry basis is the "
    "caller-declared parameter set only — no mesh/kernel "
    "inspection exists in this server, so manifold, "
    "triangle_count, and face_count are returned as null "
    "(unchecked), never as fabricated values. Unknown "
    "design_id is a -32602 error naming design_id. " + _CTXT +
    "Returns the geometry object directly.",
    {"design_id": _sp("Design id returned by design_register.")},
    ["design_id"], _ann(True, idempotent=True), _out(_GEOM))

TOOL_DEFS["design_pin_get"] = (
    "Read a design's pin state: its content pin hashes, its "
    "status (PROPOSED or ACTIVATED), its activation record, "
    "and the mandate ids that bind this pin. Use to check "
    "whether a design is printable and under which mandates; "
    "use design_inspect for geometry. Read-only: activation "
    "itself is a human-principal act outside this tool "
    "surface, and the agent-surface names "
    "design_pin_activate and profile_pin_activate are refused "
    "with AGENT_SELF_PIN_REFUSED (and the refusal is "
    "receipted). Unknown design_id is a -32602 error naming "
    "design_id. " + _CTXT + " Returns {design_id, status, pin, "
    "activation, bound_mandate_ids}.",
    {"design_id": _sp("Design id returned by design_register.")},
    ["design_id"], _ann(True, idempotent=True),
    _out({"design_id": _sp("Design requested."),
          "status": _sp("PROPOSED or ACTIVATED."),
          "pin": _PIN,
          "activation": {"type": ["object", "null"],
                         "description": "Activation record "
                         "{signer, principal, at, signature} "
                         "once a human principal has activated "
                         "the pin; null while PROPOSED."},
          "bound_mandate_ids": _ap("Mandate ids whose design_pins "
                                   "include this pin, from open "
                                   "sessions.",
                                   items={"type": "string"})},
         ["design_id", "status", "pin"]))

TOOL_DEFS["printers_discover"] = (
    "List the printers this bridge can dispatch to: serial, "
    "model, kind, firmware, firmware temperature limits, "
    "build volume, head, target class, and declared site "
    "class. Use to choose a printer_serial for a mandate or a "
    "job; use telemetry_read for a printer's live simulated "
    "state. Read-only, takes no parameters. Every printer "
    "listed is a simulator (target_class 'simulator') — this "
    "build has no real-printer target. " + _CTXT +
    "Returns {printers} with one entry per simulator.",
    {}, [], _ann(True, idempotent=True),
    _out({"printers": _ap("Simulated printers.", items={
        "type": "object", "properties": {
            "serial": _sp("Printer serial, used in mandates "
                          "and jobs."),
            "model": _sp("Printer model label."),
            "kind": _sp("Printer kind, e.g. octoprint_virtual "
                        "or klipper_virtual."),
            "firmware": _sp("Firmware label."),
            "firmware_limits": _op("Firmware temperature "
                                   "limits {hotend_max_C, "
                                   "bed_max_C, chamber_max_C}."),
            "build_volume_mm": _op("Build volume {x, y, z} in "
                                   "millimetres."),
            "head": _sp("Tool head; only 'print' heads can "
                        "take jobs."),
            "target_class": _sp("Always 'simulator' in this "
                                "build."),
            "site_class": _sp("Declared site class, e.g. "
                              "ATTENDED.")}})},
         ["printers"]))

TOOL_DEFS["session_open"] = (
    "Open a print session under a signed mandate, attesting "
    "every mandated printer's safety configuration. Use after "
    "a mandate has been signed for the agent (signing happens "
    "outside this surface) and before any job_prepare; use "
    "session_close to seal the session's evidence when done. "
    "Mutating: creates the session the later job tools bind "
    "to. The mandate is validated field by field and its "
    "Ed25519 signature must verify over the mandate exactly as "
    "presented; agent_identity must equal the mandate's "
    "agent_identity; expiry and the mandate window are checked "
    "at open, not only at dispatch; wildcard printer serials "
    "refuse; an unknown serial is a -32602 error. Tiering is "
    "fail-closed: site_class ATTENDED or UNATTENDED_RATED "
    "grants tier T1, anything else (including UNKNOWN or any "
    "unrecognized value) grants T0, which cannot prepare jobs. "
    "A printer whose safety configuration cannot be attested "
    "refuses SAFETY_CONFIG_UNVERIFIABLE. " + _CTXT +
    "Returns {session_id, tier, attestations, site_class, "
    "site_class_recognized}, where attestations maps each "
    "mandated serial to its config hash.",
    {"mandate": _op("Signed mandate object. Required fields: "
                    "agent_identity, printer_serials (non-empty "
                    "list of exact serials; wildcards refused), "
                    "design_pins, profile_pins, slicer_build "
                    "{name, version, binary_hash}, "
                    "material_class, thermal_envelope, "
                    "build_volume_bounds, max_print_duration_s, "
                    "max_filament_grams, site_class, window "
                    "{not_before, not_after} (not_after must not "
                    "exceed expiry), expiry, and signature "
                    "(Ed25519 over the mandate as presented, "
                    "excluding the signature field itself). "
                    "Optional: telemetry_gap_threshold_s "
                    "(10-300, default 30), "
                    "require_plate_clear_attested, "
                    "require_attested_loadout, "
                    "hard_stop_at_expiry."),
     "agent_identity": _sp("Presenting agent identity; must "
                           "equal the mandate's agent_identity "
                           "or the open refuses.")},
    ["mandate", "agent_identity"], _ann(False),
    _out({"session_id": _sp("New session id; all job tools "
                            "bind to it."),
          "tier": _sp("T1 for a recognized site class, T0 "
                      "otherwise (T0 cannot prepare jobs)."),
          "attestations": _op("Map of printer serial to "
                              "attested safety-config hash."),
          "site_class": _sp("Mandate site class as presented."),
          "site_class_recognized": _bp("Whether site_class is "
                                       "one of ATTENDED, "
                                       "UNATTENDED_RATED, "
                                       "UNKNOWN.")},
         ["session_id", "tier"]))

TOOL_DEFS["job_prepare"] = (
    "Prepare a print job inside an open session: re-slice the "
    "pinned design with the pinned profile on the bridge's own "
    "slicer build and return the job's canonical toolpath "
    "hash, estimates, and state. Use after session_open for an "
    "ACTIVATED design and profile whose pins are in the "
    "session mandate; use job_dispatch to send a prepared job "
    "and job_status to follow it. Mutating: creates the job "
    "record bound to this session and mandate (jobs are not "
    "portable across sessions). Checks, each refusing by name: "
    "printer must be in the mandate and tier must be T1; "
    "design must be ACTIVATED with its pin in the mandate; "
    "profile must be resolved, activated, and hash-matched to "
    "its pin and the mandate; the mandate's slicer build must "
    "equal the bridge's; the profile must satisfy the safety "
    "gauge (thermal envelope, build volume, budgets) — budget "
    "overruns refuse BUDGET_EXCEEDED_AT_PREPARE; the sliced "
    "toolpath is content-scanned and prohibited commands "
    "refuse. A supplied_toolpath is accepted only when its "
    "canonical hash equals the bridge's own slice "
    "(TOOLPATH_PROVENANCE_MISMATCH otherwise) — the bridge "
    "never prints a toolpath it did not derive from the "
    "pinned inputs. When the mandate requires an attested "
    "clear plate the job is created in "
    "PENDING_PHYSICAL_CONFIRM instead of PREPARED. " + _CTXT +
    "Returns {job_hash, toolpath_canonical_hash, raw_hash, "
    "estimates, profile_hash, slicer_build, state, "
    "pending_physical_confirm}.",
    {"session_id": _sp("Open session id from session_open."),
     "design_id": _sp("Registered, ACTIVATED design id."),
     "profile_id": _sp("Registered, ACTIVATED profile id from "
                       "design_register's profile_proposal."),
     "printer_serial": _sp("Exact printer serial; must be in "
                           "the session mandate's "
                           "printer_serials."),
     "supplied_toolpath": _sp("Optional caller-supplied "
                              "toolpath text; accepted only if "
                              "its canonical hash matches the "
                              "bridge's own re-slice of the "
                              "pinned inputs.")},
    ["session_id", "design_id", "profile_id", "printer_serial"],
    _ann(False),
    _out({"job_hash": _sp("Canonical toolpath hash; the job's "
                          "id for dispatch, status, and abort."),
          "toolpath_canonical_hash": _sp("Same value as "
                                         "job_hash."),
          "raw_hash": _sp("Hash of the raw (uncanonicalized) "
                          "toolpath text."),
          "estimates": _op("Slice estimates: duration_s, grams, "
                           "max_hotend_C, max_bed_C, "
                           "max_chamber_C, total_e_mm."),
          "profile_hash": _sp("Profile pin hash used."),
          "slicer_build": _op("Bridge slicer build {name, "
                              "version, binary_hash}."),
          "state": _sp("PREPARED, or PENDING_PHYSICAL_CONFIRM "
                       "when a physical confirmation is "
                       "outstanding."),
          "pending_physical_confirm": _ap("Outstanding physical "
                                          "confirmations, e.g. "
                                          "plate_clear.",
                                          items={"type": "string"})},
         ["job_hash", "estimates", "state"]))

TOOL_DEFS["job_dispatch"] = (
    "Dispatch a prepared job to its (simulated) printer, "
    "re-verifying everything at dispatch time. Use for a "
    "PREPARED job from job_prepare in the same session; use "
    "job_status to follow progress and job_abort to cancel. "
    "Mutating: starts the simulated print. Before starting, "
    "the bridge re-checks the mandate window and expiry "
    "(queueing is not supported — any scheduled_at value "
    "refuses, because stale authority is never queued), "
    "re-attests the printer's safety configuration against "
    "the session attestation (drift refuses CONFIG_DRIFT), "
    "checks material loadout against the mandate, confirms "
    "the evidence-pack store is available, then RE-SLICES "
    "the pinned inputs and requires the canonical hash to "
    "match the prepared job and any supplied toolpath "
    "exactly (TOOLPATH_PROVENANCE_MISMATCH otherwise) and "
    "re-scans the toolpath content. A job still in "
    "PENDING_PHYSICAL_CONFIRM returns dispatched=false with "
    "its outstanding confirmations instead of starting. " +
    _CTXT + "Returns {job_hash, state, dispatched, "
    "dispatch_record} on a start, or {job_hash, state: "
    "PENDING_PHYSICAL_CONFIRM, pending, dispatched: false}.",
    {"session_id": _sp("Session that prepared the job; a job "
                       "prepared under another session or "
                       "mandate refuses JOB_SESSION_MISMATCH."),
     "job_hash": _sp("Job hash returned by job_prepare."),
     "supplied_toolpath": _sp("Optional toolpath text; when "
                              "supplied it is dispatched only "
                              "if its canonical hash matches the "
                              "bridge's re-slice."),
     "scheduled_at": _sp("Do not supply: queueing is refused "
                         "by name (MANDATE_EXPIRED factor "
                         "queueing_not_supported_no_stale_authority) "
                         "for any value — dispatch is immediate "
                         "or not at all.")},
    ["session_id", "job_hash"], _ann(False),
    _out({"job_hash": _sp("Job dispatched or held."),
          "state": _sp("PRINTING on a start, or "
                       "PENDING_PHYSICAL_CONFIRM when held."),
          "dispatched": _bp("True only when the print "
                             "started."),
          "dispatch_record": _op("On a start: prepare_hash, "
                                 "dispatch_reslice_hash, match, "
                                 "dispatch_time, bridge_identity, "
                                 "loadout_level."),
          "pending": _ap("Outstanding physical confirmations "
                         "when held.", items={"type": "string"})},
         ["job_hash", "state", "dispatched"]))

TOOL_DEFS["job_status"] = (
    "Read a job's current state, live simulated telemetry, "
    "budget consumption, and outstanding physical "
    "confirmations. Use to follow a dispatched job; use "
    "telemetry_read for printer telemetry without a job "
    "context and job_abort to cancel. Read-only: reading "
    "status advances nothing — simulated time and progress "
    "move only while the bridge processes the print. The job "
    "must belong to the presented session and mandate "
    "(JOB_SESSION_MISMATCH otherwise); unknown job_hash is a "
    "-32602 error. " + _CTXT + " Returns {job_hash, state, "
    "telemetry, budget_consumption, pending_physical_confirm}; "
    "telemetry is null while the printer's telemetry is cut.",
    {"session_id": _sp("Session that prepared the job."),
     "job_hash": _sp("Job hash returned by job_prepare.")},
    ["session_id", "job_hash"], _ann(True, idempotent=True),
    _out({"job_hash": _sp("Job requested."),
          "state": _sp("PREPARED, PENDING_PHYSICAL_CONFIRM, "
                       "PRINTING, PAUSED, PAUSED_TELEMETRY_GAP, "
                       "PAUSED_AT_CLOSE, COMPLETED, or ABORTED."),
          "telemetry": {"type": ["object", "null"],
                        "description": "Simulated telemetry "
                        "snapshot {hotend_C, bed_C, "
                        "target_hotend_C, target_bed_C, "
                        "progress, elapsed_s, state, fan_pct, "
                        "power_w}, or null during a telemetry "
                        "cut."},
          "budget_consumption": _op("Estimated consumption so "
                                    "far: grams_estimate and "
                                    "elapsed_s."),
          "pending_physical_confirm": _ap("Outstanding physical "
                                          "confirmations.",
                                          items={"type": "string"})},
         ["job_hash", "state"]))

TOOL_DEFS["job_abort"] = (
    "Abort a job and cancel its simulated print: the printer "
    "returns to idle and cools, and the job's state becomes "
    "ABORTED permanently. Use to stop a prepared or printing "
    "job; use job_status first to confirm the job's state if "
    "unsure. Destructive and irreversible within the session: "
    "an aborted job cannot be resumed or re-dispatched — "
    "prepare a new job to print again. The abort is receipted "
    "in the server's refusal/receipt log and the job's end "
    "state is sealed into the session evidence pack at "
    "session_close. Aborting an already-aborted job returns "
    "the same ABORTED result. The job must belong to the "
    "presented session and mandate (JOB_SESSION_MISMATCH "
    "otherwise); unknown job_hash is a -32602 error. " +
    _CTXT + " Returns {job_hash, state: ABORTED, receipted: "
    "true}.",
    {"session_id": _sp("Session that prepared the job."),
     "job_hash": _sp("Job hash returned by job_prepare.")},
    ["session_id", "job_hash"], _ann(False, destructive=True,
                                     idempotent=True),
    _out({"job_hash": _sp("Job aborted."),
          "state": _sp("ABORTED."),
          "receipted": _bp("Always true: the abort was "
                           "receipted.")},
         ["job_hash", "state", "receipted"]))

TOOL_DEFS["telemetry_read"] = (
    "Read one mandated printer's current simulated telemetry "
    "snapshot: hotend and bed temperatures and targets, "
    "progress, elapsed seconds, state, fan, and power. Use "
    "for printer state outside a job; use job_status for a "
    "job's state plus its telemetry and budgets. Read-only. "
    "The printer must be in the session mandate's "
    "printer_serials (otherwise a -32602 error naming "
    "printer_serial). During a telemetry cut this returns "
    "{state: UNKNOWN, telemetry: null} — an honest gap, "
    "never interpolated values. " + _CTXT + " Returns the "
    "telemetry object directly.",
    {"session_id": _sp("Open session id from session_open."),
     "printer_serial": _sp("Printer serial in the session "
                           "mandate.")},
    ["session_id", "printer_serial"], _ann(True, idempotent=True),
    _out({"hotend_C": _np("Current simulated hotend "
                          "temperature."),
          "bed_C": _np("Current simulated bed temperature."),
          "target_hotend_C": _np("Target hotend temperature "
                                 "(0 when not heating)."),
          "target_bed_C": _np("Target bed temperature (0 when "
                              "not heating)."),
          "progress": _np("Print progress fraction 0 to 1."),
          "elapsed_s": _np("Simulated print elapsed seconds."),
          "state": _sp("Printer state, e.g. idle, printing, "
                       "paused, completed, or UNKNOWN on a "
                       "telemetry cut."),
          "fan_pct": _np("Simulated fan percent."),
          "power_w": _np("Simulated power draw in watts."),
          "telemetry": {"type": ["object", "null"],
                        "description": "Null only in the "
                        "telemetry-cut shape, where state is "
                        "UNKNOWN."}}))

TOOL_DEFS["session_close"] = (
    "Close a session and seal its evidence: for every job in "
    "the session, build and sign a full evidence pack "
    "(printer and firmware attestation, mandate record and "
    "hash, design pin and activation, slicer build, profile, "
    "toolpath hashes, dispatch record, telemetry digest, "
    "loadout, readiness facts, budgets, refusals, gaps, "
    "events, and end state) and write it to the pack store on "
    "disk; a session with no jobs seals a refusal-only pack. "
    "Use when the session's work is done; use session_open to "
    "start a new session afterwards. Mutating and final: a "
    "job still PRINTING is recorded PAUSED_AT_CLOSE, the "
    "session is marked closed, and every later call naming "
    "this session refuses SESSION_NOT_FOUND — closing twice "
    "is not possible. There is no raw-command path at any "
    "point in this surface: tool names for raw G-code, "
    "config writes, firmware updates, or agent pin activation "
    "are refused by name and receipted. " + _CTXT +
    "Returns {session_id, packs, pack_ids} with the full "
    "sealed pack objects.",
    {"session_id": _sp("Open session id from session_open.")},
    ["session_id"], _ann(False),
    _out({"session_id": _sp("Session closed."),
          "packs": _ap("Sealed, signed evidence pack objects, "
                       "one per job (or one refusal-only pack).",
                       items={"type": "object"}),
          "pack_ids": _ap("Ids of the sealed packs.",
                          items={"type": "string"})},
         ["session_id", "pack_ids"]))


def handle(req):
    method = req.get("method"); rid = req.get("id")
    if method == "initialize":
        return {"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},
                "serverInfo":{"name":"Eclipse Loft","version":eng.VERSION,"description":DESCRIPTOR}}}
    if method == "tools/list":
        return {"jsonrpc":"2.0","id":rid,"result":{"tools":[
            {"name":t,"description":TOOL_DEFS[t][0],
             "inputSchema":{"type":"object","properties":TOOL_DEFS[t][1],"required":TOOL_DEFS[t][2]},
             "annotations":TOOL_DEFS[t][3],"outputSchema":TOOL_DEFS[t][4]} for t in TOOLS]}}
    if method == "tools/call":
        params = req.get("params") or {}
        if not isinstance(params, dict):
            return {"jsonrpc":"2.0","id":rid,"error":{"code":-32602,"message":"INVALID_PARAMS: argument 'params'"}}
        try:
            result = call_tool(params.get("name"), params.get("arguments"))
            return {"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":json.dumps(result, default=str)}], **({"isError": True} if isinstance(result, dict) and result.get("is_error") else {})}}
        except ToolError as e:
            return {"jsonrpc":"2.0","id":rid,"error":{"code":e.code,"message":f"{e.refusal or 'INVALID_PARAMS'}: argument '{e.arg}'"}}
        except Exception:
            # D3 house envelope hygiene: a malformed container NEVER kills stdio and
            # never surfaces as a bare -32603/traceback — named -32602, server lives.
            return {"jsonrpc":"2.0","id":rid,"error":{"code":-32602,"message":"MALFORMED_CONTAINER: argument 'tools/call'"}}
    return {"jsonrpc":"2.0","id":rid,"error":{"code":-32602,"message":f"UNKNOWN_METHOD: '{method}'"}}

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try: req = json.loads(line)
        except Exception:
            sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":None,"error":{"code":-32700,"message":"PARSE_ERROR"}})+"\n"); sys.stdout.flush(); continue
        if not isinstance(req, dict):
            sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":None,"error":{"code":-32602,"message":"INVALID_REQUEST: argument 'request'"}})+"\n"); sys.stdout.flush(); continue
        try: out = handle(req)
        except Exception:
            out = {"jsonrpc":"2.0","id":req.get("id"),"error":{"code":-32602,"message":"MALFORMED_CONTAINER: argument 'request'"}}
        if req.get("id") is not None: sys.stdout.write(json.dumps(out)+"\n"); sys.stdout.flush()

if __name__ == "__main__": main()
# Eclipse Loft MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai

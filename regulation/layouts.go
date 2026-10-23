package regulation

import (
	"fmt"
	"sort"
	"strings"
)

// TableLayout is the single source of truth for one embedded PARAM's identity
// and geometry. Every table the workspace's tools read or write is declared here
// once, so a row size is never restated at a use site.
//
// RowSize is the stride the *shipped regulation* actually uses, which is not
// always what the pinned Paramdex definition declares. BuddyParam is the case
// that motivated this registry: Paramdex declares 96 bytes and the regulation
// uses 160, and a constant copied faithfully from the definition silently hid
// 64 bytes of real fields for the entire life of the summon research. Validating
// against both sources is therefore the point, not a formality.
type TableLayout struct {
	// Table is the bare name, matching the Paramdex Names file.
	Table string
	// Entry is the binder entry basename inside the regulation.
	Entry string
	// SchemaFile is the Paramdex definition basename when it differs from Table.
	SchemaFile string
	// ParamType and DataVersion identify the row format.
	ParamType   string
	DataVersion int16
	// RowSize is the observed stride in the shipped regulation.
	RowSize int
	// SchemaShortfall records, in bytes, how much of the row the pinned
	// definition fails to describe. Zero means the definition is complete.
	SchemaShortfall int
	// SingleRow declares a table that ships exactly one row. A stride cannot be
	// derived from one row, so RowSize is taken from the pinned definition
	// instead of being cross-checked against the regulation. Declaring it keeps
	// the invariant test meaningful rather than tolerating a blanket mismatch.
	SingleRow bool
	// Note explains a known discrepancy so it is not rediscovered.
	Note string
}

// SchemaName is the Paramdex definition basename for this table.
func (layout TableLayout) SchemaName() string {
	if layout.SchemaFile != "" {
		return layout.SchemaFile
	}
	return layout.Table
}

// paramLayouts is ordered for stable reporting. Values are measured from the
// regulation, not copied from Paramdex.
var paramLayouts = []TableLayout{
	{Table: "SpEffectParam", Entry: "SpEffectParam.param", SchemaFile: "SpEffect",
		ParamType: "SP_EFFECT_PARAM_ST", DataVersion: 4, RowSize: 912},
	{Table: "SpEffectVfxParam", Entry: "SpEffectVfxParam.param", SchemaFile: "SpEffectVfx",
		ParamType: "SP_EFFECT_VFX_PARAM_ST", DataVersion: 1, RowSize: 164},
	{Table: "EquipParamGoods", Entry: "EquipParamGoods.param",
		ParamType: "EQUIP_PARAM_GOODS_ST", DataVersion: 3, RowSize: 176},
	{Table: "EquipParamProtector", Entry: "EquipParamProtector.param",
		ParamType: "EQUIP_PARAM_PROTECTOR_ST", DataVersion: 6, RowSize: 416},
	{Table: "EquipParamAccessory", Entry: "EquipParamAccessory.param",
		ParamType: "EQUIP_PARAM_ACCESSORY_ST", DataVersion: 2, RowSize: 96},
	{Table: "EquipParamWeapon", Entry: "EquipParamWeapon.param",
		ParamType: "EQUIP_PARAM_WEAPON_ST", DataVersion: 6, RowSize: 664},
	{Table: "BuddyParam", Entry: "BuddyParam.param",
		ParamType: "BUDDY_PARAM_ST", DataVersion: 2, RowSize: 160, SchemaShortfall: 64,
		Note: "Paramdex declares 29 fields totalling 96 bytes, upstream master included. " +
			"Offsets 96-128 hold a nine-slot SpEffect array, 132-148 a five-slot array, " +
			"and 152-159 are zero. Read them with param-rows -bytes."},
	{Table: "NpcParam", Entry: "NpcParam.param",
		ParamType: "NPC_PARAM_ST", DataVersion: 9, RowSize: 736},
	{Table: "NpcThinkParam", Entry: "NpcThinkParam.param",
		ParamType: "NPC_THINK_PARAM_ST", DataVersion: 2, RowSize: 228},
	{Table: "PhantomParam", Entry: "PhantomParam.param",
		ParamType: "PHANTOM_PARAM_ST", DataVersion: 3, RowSize: 56},
	{Table: "MapMimicryEstablishmentParam", Entry: "MapMimicryEstablishmentParam.param",
		ParamType: "MAP_MIMICRY_ESTABLISHMENT_PARAM_ST", DataVersion: 1, RowSize: 64},
	{Table: "BuddyStoneParam", Entry: "BuddyStoneParam.param",
		ParamType: "BUDDY_STONE_PARAM_ST", DataVersion: 2, RowSize: 64},
	{Table: "CharaInitParam", Entry: "CharaInitParam.param",
		ParamType: "CHARACTER_INIT_PARAM", DataVersion: 2, RowSize: 320},
	{Table: "ShopLineupParam", Entry: "ShopLineupParam.param",
		ParamType: "SHOP_LINEUP_PARAM", DataVersion: 3, RowSize: 52},
	{Table: "RoleParam", Entry: "RoleParam.param",
		ParamType: "ROLE_PARAM_ST", DataVersion: 2, RowSize: 128,
		Note: "Multiplayer role definitions. teamType is the friend/foe axis and the " +
			"ten spEffectID slots are applied to a player occupying the role."},
	{Table: "NetworkParam", Entry: "NetworkParam.param",
		ParamType: "NETWORK_PARAM_ST", DataVersion: 10, RowSize: 632, SingleRow: true,
		Note: "Row 0 holds the matchmaking timings and capacities. The pad at 0x7C " +
			"holds vanilla 5 and is read as breakInRequestAreaCount."},
	{Table: "MenuCommonParam", Entry: "MenuCommonParam.param",
		ParamType: "MENU_COMMON_PARAM_ST", DataVersion: 1, RowSize: 256, SingleRow: true,
		Note: "Single row of front-end constants. The three compass distances are an " +
			"inner cutoff: a player is drawn when further away than the value, so the " +
			"hostile host's 30 is a blackout radius against 0 for both friendly entries."},
	{Table: "FaceRangeParam", Entry: "FaceRangeParam.param",
		ParamType: "FACE_RANGE_PARAM_ST", DataVersion: 3, RowSize: 824,
		Note: "Two-row minimum/maximum bounds table for the character creation " +
			"parameters: row 1 is the floor and row 2 the ceiling for 206 fields, " +
			"with eyeR_irisScale and decal_scale inverted. Each u8 creation byte " +
			"in the save's FACE record maps onto its field's row1..row2 range, so " +
			"the ceiling is what limits a result rather than the byte. The five " +
			"chrBodyScale entries ship at -1..+1, which is why a body scale " +
			"written at 255 lands exactly on the creator's own maximum."},
	{Table: "WetAspectParam", Entry: "WetAspectParam.param",
		ParamType: "WET_ASPECT_PARAM_ST", DataVersion: 1, RowSize: 32,
		Note: "Player material overlay, reached from SpEffectVfxParam.wetAspectType " +
			"by row ID. The 20 rows are fully described: three u8 base colour " +
			"channels, an f32 alpha, a metallic value and rate, and a shininess " +
			"rate and value, with every remaining byte a declared reserve. Rows " +
			"0, 8, 9, 12, 13, 14, 15 and 16 are entirely default, so the seven " +
			"besides native-dry row 0 are free scratch space."},
	{Table: "Bullet", Entry: "Bullet.param", SchemaFile: "BulletParam",
		ParamType: "BULLET_PARAM_ST", DataVersion: 4, RowSize: 272,
		Note: "The entry is Bullet.param but the definition is BulletParam.xml, the " +
			"same trap as SpEffectParam/SpEffect.xml. Goods with refCategory 1 " +
			"reach their effect through this table."},
}

var layoutsByTable = func() map[string]TableLayout {
	index := make(map[string]TableLayout, len(paramLayouts))
	for _, layout := range paramLayouts {
		index[layout.Table] = layout
		index[layout.Entry] = layout
	}
	return index
}()

// LayoutFor resolves a registered table by bare name or binder entry name.
func LayoutFor(table string) (TableLayout, bool) {
	layout, present := layoutsByTable[strings.TrimSpace(table)]
	return layout, present
}

// MustLayout is for the declaration of derived constants, where an unregistered
// table is a programming error rather than a runtime condition.
func MustLayout(table string) TableLayout {
	layout, present := LayoutFor(table)
	if !present {
		panic("unregistered PARAM table " + table)
	}
	return layout
}

func (layout TableLayout) verifyHeader(header *ParamHeader) error {
	if header.ParamType != layout.ParamType || header.DataVersion != layout.DataVersion {
		return fmt.Errorf("%s is %q/%d, the registry declares %q/%d",
			layout.Entry, header.ParamType, header.DataVersion, layout.ParamType, layout.DataVersion)
	}
	return nil
}

// LayoutCheck reports one table's registry agreement.
type LayoutCheck struct {
	Table           string `json:"table"`
	Entry           string `json:"entry"`
	ParamType       string `json:"param_type"`
	DataVersion     int16  `json:"data_version"`
	RowCount        int    `json:"row_count"`
	RegistryRowSize int    `json:"registry_row_size"`
	ObservedRowSize int    `json:"observed_row_size"`
	SchemaRowSize   int    `json:"schema_row_size,omitempty"`
	SchemaShortfall int    `json:"schema_shortfall,omitempty"`
	Status          string `json:"status"`
	Note            string `json:"note,omitempty"`
}

// VerifyParamLayouts checks every registered table against the regulation and,
// when a Paramdex checkout is supplied, against the pinned definition too. It is
// the guard that would have caught the BuddyParam shortfall on first contact.
func VerifyParamLayouts(savePath, paramdexRoot string) ([]LayoutCheck, error) {
	regulation, err := Load(savePath)
	if err != nil {
		return nil, err
	}
	checks := make([]LayoutCheck, 0, len(paramLayouts))
	for _, layout := range paramLayouts {
		check := LayoutCheck{
			Table: layout.Table, Entry: layout.Entry, ParamType: layout.ParamType,
			DataVersion: layout.DataVersion, RegistryRowSize: layout.RowSize,
			SchemaShortfall: layout.SchemaShortfall, Note: layout.Note,
		}
		var problems []string
		_, data, header, rows, err := LoadParamRows(regulation.BND4, layout.Entry)
		if err != nil {
			check.Status = "unreadable: " + err.Error()
			checks = append(checks, check)
			continue
		}
		check.RowCount = len(rows)
		if err := layout.verifyHeader(header); err != nil {
			problems = append(problems, err.Error())
		}
		switch {
		case layout.SingleRow:
			if len(rows) != 1 {
				problems = append(problems, fmt.Sprintf("declared single-row table holds %d rows", len(rows)))
			}
		default:
			if observed, err := UniformRowSize(data, rows); err != nil {
				problems = append(problems, err.Error())
			} else {
				check.ObservedRowSize = observed
				if observed != layout.RowSize {
					problems = append(problems, fmt.Sprintf("regulation stride %d does not match registry %d", observed, layout.RowSize))
				}
			}
		}
		if strings.TrimSpace(paramdexRoot) != "" {
			schema, err := LoadParamdexSchema(paramdexRoot, "ER", layout.SchemaName(), regulation.Version)
			switch {
			case err != nil:
				problems = append(problems, "paramdex: "+err.Error())
			default:
				check.SchemaRowSize = schema.RowSize
				shortfall := layout.RowSize - schema.RowSize
				if shortfall != layout.SchemaShortfall {
					problems = append(problems, fmt.Sprintf(
						"pinned definition describes %d of %d bytes, an undeclared shortfall of %d",
						schema.RowSize, layout.RowSize, shortfall))
				}
			}
		}
		switch {
		case len(problems) > 0:
			check.Status = "MISMATCH: " + strings.Join(problems, "; ")
		case layout.SchemaShortfall > 0:
			check.Status = "ok, definition is short by a known amount"
		case layout.SingleRow:
			check.Status = "ok, single-row table with no derivable stride"
		default:
			check.Status = "ok"
		}
		checks = append(checks, check)
	}
	sort.SliceStable(checks, func(i, j int) bool { return checks[i].Table < checks[j].Table })
	return checks, nil
}

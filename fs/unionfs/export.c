/*
 * unionfs functions that are exported outside for
 * sting's use.
 */

#include "union.h"

struct dentry *unionfs_lower_dentry_idx_export(
				const struct dentry *dent,
				int index)
{
	return unionfs_lower_dentry_idx(dent, index);
}
EXPORT_SYMBOL(unionfs_lower_dentry_idx_export);

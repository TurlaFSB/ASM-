// Tags are typed as comma-separated text; the server normalises and validates them.
export const parseTags = (text) => text.split(/[,;]+/).map(x => x.trim()).filter(Boolean);

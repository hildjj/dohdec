
import fs from 'node:fs/promises';

let localSet = new Set();
try {
  // eslint-disable-next-line n/no-top-level-await
  const deps = await Promise.any([
    fs.readFile('../deps.json', 'utf8'),
    fs.readFile('../../deps.json', 'utf8'),
  ]);
  const {local} = JSON.parse(deps);
  localSet = new Set(local);
} catch (errs) {
  const badErrs = errs.errors.filter(e => e.code !== 'ENOENT');
  switch (badErrs.length) {
    case 0:
      break;
    case 1:
      throw badErrs[0];
    default:
      throw new AggregateError(badErrs, 'Error finding dependencies', {cause: errs});
  }
}

export default {
  dep: ['prod', 'dev', 'packageManager'],
  cooldown: packageName => (localSet.has(packageName) ? 0 : 7),
};

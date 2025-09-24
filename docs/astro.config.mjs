// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	integrations: [
		starlight({
			title: 'LeafLock',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/RelativeSure/LeafLock' }],
			sidebar: [
				{
					label: 'Admin',
					autogenerate: { directory: 'admin' },
				},
				{
					label: 'Guides',
					autogenerate: { directory: 'guides' },
				},
				{
					label: 'Legal',
					autogenerate: { directory: 'legal' },
				},
				{
					label: 'Reference',
					autogenerate: { directory: 'reference' },
				},
			],
		}),
	],
});

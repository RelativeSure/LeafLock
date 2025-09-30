// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://leaflock.app',
	integrations: [
		starlight({
			title: 'LeafLock',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/RelativeSure/LeafLock' }],
			sidebar: [
				{
					label: 'Guides',
					autogenerate: { directory: 'guides' },
				},
				{
					label: 'Deployment',
					autogenerate: { directory: 'deployment' },
				},
				{
					label: 'Troubleshooting',
					autogenerate: { directory: 'troubleshooting' },
				},
				{
					label: 'Administration',
					autogenerate: { directory: 'admin' },
				},
				{
					label: 'Development',
					autogenerate: { directory: 'development' },
				},
				{
					label: 'Reference',
					autogenerate: { directory: 'reference' },
				},
				{
					label: 'Legal',
					autogenerate: { directory: 'legal' },
				},
			],
		}),
	],
});

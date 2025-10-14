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
				{ label: 'Overview', items: [{ label: 'LeafLock Docs', link: '/' }] },
				{ label: 'Getting Started', autogenerate: { directory: 'getting-started' } },
				{ label: 'Architecture', autogenerate: { directory: 'architecture' } },
				{ label: 'Features', autogenerate: { directory: 'features' } },
				{ label: 'Deployment', autogenerate: { directory: 'deployment' } },
				{ label: 'Operations', autogenerate: { directory: 'operations' } },
				{ label: 'API', autogenerate: { directory: 'api' } },
				{ label: 'Troubleshooting', autogenerate: { directory: 'troubleshooting' } },
				{ label: 'Legal', autogenerate: { directory: 'legal' } },
				{ label: 'Swagger', autogenerate: { directory: 'swagger' } },
			],
		}),
	],
});

import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// Import all UI components
import { Button } from './button.jsx';
import { Input } from './input.jsx';
import { Textarea } from './textarea.jsx';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from './card.jsx';
import { Badge } from './badge.jsx';
import { Alert, AlertDescription, AlertTitle } from './alert.jsx';
import { Separator } from './separator.jsx';
import { ScrollArea } from './scroll-area.jsx';

describe('shadcn/ui Components', () => {
  describe('Button Component', () => {
    it('renders with default variant and size', () => {
      render(<Button>Click me</Button>);
      
      const button = screen.getByRole('button');
      expect(button).toBeInTheDocument();
      expect(button).toHaveTextContent('Click me');
      expect(button).toHaveClass('bg-primary');
    });

    it('renders different variants', () => {
      const { rerender } = render(<Button variant="destructive">Delete</Button>);
      expect(screen.getByRole('button')).toHaveClass('bg-destructive');

      rerender(<Button variant="outline">Outline</Button>);
      expect(screen.getByRole('button')).toHaveClass('border');

      rerender(<Button variant="secondary">Secondary</Button>);
      expect(screen.getByRole('button')).toHaveClass('bg-secondary');

      rerender(<Button variant="ghost">Ghost</Button>);
      expect(screen.getByRole('button')).toHaveClass('hover:bg-accent');

      rerender(<Button variant="link">Link</Button>);
      expect(screen.getByRole('button')).toHaveClass('underline-offset-4');
    });

    it('renders different sizes', () => {
      const { rerender } = render(<Button size="sm">Small</Button>);
      expect(screen.getByRole('button')).toHaveClass('h-9');

      rerender(<Button size="lg">Large</Button>);
      expect(screen.getByRole('button')).toHaveClass('h-11');

      rerender(<Button size="icon">Icon</Button>);
      expect(screen.getByRole('button')).toHaveClass('h-10', 'w-10');
    });

    it('handles click events', async () => {
      const handleClick = vi.fn();
      const user = userEvent.setup();
      
      render(<Button onClick={handleClick}>Click me</Button>);
      
      await user.click(screen.getByRole('button'));
      expect(handleClick).toHaveBeenCalledTimes(1);
    });

    it('is disabled when disabled prop is true', () => {
      render(<Button disabled>Disabled</Button>);
      
      const button = screen.getByRole('button');
      expect(button).toBeDisabled();
      expect(button).toHaveClass('disabled:opacity-50');
    });

    it('forwards ref correctly', () => {
      const ref = vi.fn();
      render(<Button ref={ref}>Button</Button>);
      
      expect(ref).toHaveBeenCalledWith(expect.any(HTMLButtonElement));
    });
  });

  describe('Input Component', () => {
    it('renders input element', () => {
      render(<Input placeholder="Enter text" />);
      
      const input = screen.getByPlaceholderText('Enter text');
      expect(input).toBeInTheDocument();
      expect(input).toHaveAttribute('type', 'text');
    });

    it('handles different input types', () => {
      render(<Input type="email" placeholder="Email" />);
      
      const input = screen.getByPlaceholderText('Email');
      expect(input).toHaveAttribute('type', 'email');
    });

    it('handles value changes', async () => {
      const handleChange = vi.fn();
      const user = userEvent.setup();
      
      render(<Input onChange={handleChange} placeholder="Type here" />);
      
      const input = screen.getByPlaceholderText('Type here');
      await user.type(input, 'Hello');
      
      expect(handleChange).toHaveBeenCalled();
      expect(input).toHaveValue('Hello');
    });

    it('forwards ref correctly', () => {
      const ref = vi.fn();
      render(<Input ref={ref} />);
      
      expect(ref).toHaveBeenCalledWith(expect.any(HTMLInputElement));
    });
  });

  describe('Textarea Component', () => {
    it('renders textarea element', () => {
      render(<Textarea placeholder="Enter long text" />);
      
      const textarea = screen.getByPlaceholderText('Enter long text');
      expect(textarea).toBeInTheDocument();
      expect(textarea.tagName).toBe('TEXTAREA');
    });

    it('handles value changes', async () => {
      const handleChange = vi.fn();
      const user = userEvent.setup();
      
      render(<Textarea onChange={handleChange} placeholder="Type here" />);
      
      const textarea = screen.getByPlaceholderText('Type here');
      await user.type(textarea, 'Multi-line\ntext content');
      
      expect(handleChange).toHaveBeenCalled();
      expect(textarea).toHaveValue('Multi-line\ntext content');
    });

    it('forwards ref correctly', () => {
      const ref = vi.fn();
      render(<Textarea ref={ref} />);
      
      expect(ref).toHaveBeenCalledWith(expect.any(HTMLTextAreaElement));
    });
  });

  describe('Card Component', () => {
    it('renders card structure correctly', () => {
      render(
        <Card>
          <CardHeader>
            <CardTitle>Card Title</CardTitle>
            <CardDescription>Card description</CardDescription>
          </CardHeader>
          <CardContent>
            <p>Card content</p>
          </CardContent>
          <CardFooter>
            <Button>Action</Button>
          </CardFooter>
        </Card>
      );

      expect(screen.getByText('Card Title')).toBeInTheDocument();
      expect(screen.getByText('Card description')).toBeInTheDocument();
      expect(screen.getByText('Card content')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Action' })).toBeInTheDocument();
    });

    it('applies proper CSS classes', () => {
      render(
        <Card data-testid="card">
          <CardHeader data-testid="header">
            <CardTitle data-testid="title">Title</CardTitle>
            <CardDescription data-testid="description">Description</CardDescription>
          </CardHeader>
          <CardContent data-testid="content">Content</CardContent>
          <CardFooter data-testid="footer">Footer</CardFooter>
        </Card>
      );

      expect(screen.getByTestId('card')).toHaveClass('rounded-lg', 'border', 'bg-card');
      expect(screen.getByTestId('header')).toHaveClass('flex', 'flex-col', 'space-y-1.5');
      expect(screen.getByTestId('title')).toHaveClass('text-2xl', 'font-semibold');
      expect(screen.getByTestId('description')).toHaveClass('text-sm', 'text-muted-foreground');
    });
  });

  describe('Badge Component', () => {
    it('renders with default variant', () => {
      render(<Badge>Default Badge</Badge>);
      
      const badge = screen.getByText('Default Badge');
      expect(badge).toBeInTheDocument();
      expect(badge).toHaveClass('bg-primary');
    });

    it('renders different variants', () => {
      const { rerender } = render(<Badge variant="secondary">Secondary</Badge>);
      expect(screen.getByText('Secondary')).toHaveClass('bg-secondary');

      rerender(<Badge variant="destructive">Destructive</Badge>);
      expect(screen.getByText('Destructive')).toHaveClass('bg-destructive');

      rerender(<Badge variant="outline">Outline</Badge>);
      expect(screen.getByText('Outline')).toHaveClass('border');
    });
  });

  describe('Alert Component', () => {
    it('renders alert with title and description', () => {
      render(
        <Alert>
          <AlertTitle>Alert Title</AlertTitle>
          <AlertDescription>This is an alert description</AlertDescription>
        </Alert>
      );

      expect(screen.getByText('Alert Title')).toBeInTheDocument();
      expect(screen.getByText('This is an alert description')).toBeInTheDocument();
    });

    it('renders different variants', () => {
      const { rerender } = render(
        <Alert variant="destructive" data-testid="alert">
          <AlertDescription>Error alert</AlertDescription>
        </Alert>
      );
      expect(screen.getByTestId('alert')).toHaveClass('border-destructive/50');

      rerender(
        <Alert variant="default" data-testid="alert">
          <AlertDescription>Default alert</AlertDescription>
        </Alert>
      );
      expect(screen.getByTestId('alert')).toHaveClass('border');
    });
  });

  describe('Separator Component', () => {
    it('renders horizontal separator by default', () => {
      render(<Separator data-testid="separator" />);
      
      const separator = screen.getByTestId('separator');
      expect(separator).toBeInTheDocument();
      expect(separator).toHaveClass('h-[1px]', 'w-full');
    });

    it('renders vertical separator', () => {
      render(<Separator orientation="vertical" data-testid="separator" />);
      
      const separator = screen.getByTestId('separator');
      expect(separator).toHaveClass('h-full', 'w-[1px]');
    });
  });

  describe('ScrollArea Component', () => {
    it('renders scroll area with content', () => {
      render(
        <ScrollArea className="h-20 w-48" data-testid="scroll-area">
          <div className="p-4">
            <p>Item 1</p>
            <p>Item 2</p>
            <p>Item 3</p>
            <p>Item 4</p>
            <p>Item 5</p>
          </div>
        </ScrollArea>
      );

      const scrollArea = screen.getByTestId('scroll-area');
      expect(scrollArea).toBeInTheDocument();
      expect(screen.getByText('Item 1')).toBeInTheDocument();
      expect(screen.getByText('Item 5')).toBeInTheDocument();
    });
  });

  describe('Component Integration', () => {
    it('works together in a form layout', async () => {
      const handleSubmit = vi.fn();
      const user = userEvent.setup();

      render(
        <Card>
          <CardHeader>
            <CardTitle>Contact Form</CardTitle>
            <CardDescription>Fill out the form below</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label htmlFor="name">Name</label>
              <Input id="name" placeholder="Enter your name" />
            </div>
            <div>
              <label htmlFor="message">Message</label>
              <Textarea id="message" placeholder="Enter your message" />
            </div>
            <Alert>
              <AlertTitle>Notice</AlertTitle>
              <AlertDescription>All fields are required</AlertDescription>
            </Alert>
          </CardContent>
          <Separator />
          <CardFooter className="space-x-2">
            <Button onClick={handleSubmit}>Submit</Button>
            <Button variant="outline">Cancel</Button>
            <Badge variant="secondary">Draft</Badge>
          </CardFooter>
        </Card>
      );

      // Verify form structure
      expect(screen.getByText('Contact Form')).toBeInTheDocument();
      expect(screen.getByLabelText('Name')).toBeInTheDocument();
      expect(screen.getByLabelText('Message')).toBeInTheDocument();
      expect(screen.getByText('All fields are required')).toBeInTheDocument();
      expect(screen.getByText('Draft')).toBeInTheDocument();

      // Test interactions
      await user.type(screen.getByLabelText('Name'), 'John Doe');
      await user.type(screen.getByLabelText('Message'), 'Hello world');
      await user.click(screen.getByRole('button', { name: 'Submit' }));

      expect(handleSubmit).toHaveBeenCalledTimes(1);
    });
  });

  describe('Accessibility Features', () => {
    it('buttons have proper accessibility attributes', () => {
      render(
        <div>
          <Button aria-label="Primary action">Action</Button>
          <Button disabled aria-label="Disabled action">Disabled</Button>
        </div>
      );

      const buttons = screen.getAllByRole('button');
      expect(buttons[0]).toHaveAttribute('aria-label', 'Primary action');
      expect(buttons[1]).toHaveAttribute('aria-label', 'Disabled action');
      expect(buttons[1]).toHaveAttribute('aria-disabled', 'true');
    });

    it('form controls have proper labels', () => {
      render(
        <div>
          <label htmlFor="test-input">Test Input</label>
          <Input id="test-input" aria-describedby="input-help" />
          <div id="input-help">Help text for input</div>
          
          <label htmlFor="test-textarea">Test Textarea</label>
          <Textarea id="test-textarea" aria-describedby="textarea-help" />
          <div id="textarea-help">Help text for textarea</div>
        </div>
      );

      const input = screen.getByLabelText('Test Input');
      const textarea = screen.getByLabelText('Test Textarea');

      expect(input).toHaveAttribute('aria-describedby', 'input-help');
      expect(textarea).toHaveAttribute('aria-describedby', 'textarea-help');
    });

    it('alerts have proper ARIA roles', () => {
      render(
        <div>
          <Alert role="alert">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>Something went wrong</AlertDescription>
          </Alert>
          
          <Alert role="status">
            <AlertTitle>Success</AlertTitle>
            <AlertDescription>Operation completed</AlertDescription>
          </Alert>
        </div>
      );

      const alerts = screen.getAllByRole('alert');
      expect(alerts[0]).toHaveTextContent('Error');
      
      const status = screen.getByRole('status');
      expect(status).toHaveTextContent('Success');
    });
  });

  describe('Keyboard Navigation', () => {
    it('supports keyboard navigation for interactive elements', async () => {
      const user = userEvent.setup();

      render(
        <div>
          <Button>First</Button>
          <Button>Second</Button>
          <Input placeholder="Input field" />
          <Textarea placeholder="Textarea field" />
        </div>
      );

      // Test tab navigation
      await user.tab();
      expect(screen.getByRole('button', { name: 'First' })).toHaveFocus();

      await user.tab();
      expect(screen.getByRole('button', { name: 'Second' })).toHaveFocus();

      await user.tab();
      expect(screen.getByPlaceholderText('Input field')).toHaveFocus();

      await user.tab();
      expect(screen.getByPlaceholderText('Textarea field')).toHaveFocus();
    });

    it('handles Enter key on buttons', async () => {
      const handleClick = vi.fn();
      const user = userEvent.setup();

      render(<Button onClick={handleClick}>Press Enter</Button>);

      const button = screen.getByRole('button');
      button.focus();
      await user.keyboard('{Enter}');

      expect(handleClick).toHaveBeenCalledTimes(1);
    });
  });
});